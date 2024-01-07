package daemon

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	kubeErrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"

	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	ctrlcommon "github.com/openshift/machine-config-operator/pkg/controller/common"
	"github.com/openshift/machine-config-operator/pkg/daemon/constants"
)

// RunOnceInDeviceAgentMode performs a single, clusterless update in agent mode
func (dn *Daemon) RunOnceInDeviceAgentMode(currentConfig, desiredConfig *mcfgv1.MachineConfig, skipCertificateWrite, skipReboot bool) (bool, error) {
	dn.skipReboot = skipReboot

	// Shut down the Config Drift Monitor since we'll be performing an update
	// and the config will "drift" while the update is occurring.
	dn.stopConfigDriftMonitor()

	return dn.updateInDeviceAgentMode(currentConfig, desiredConfig, skipCertificateWrite)
}

// updateInDeviceAgentMode() is a copy of the update() function, with the following changes:
// * Do not perform reboot, but return whether a reboot is required. The caller will need to reboot later.
// * Do not signal the need for reboot when systemd units change. The caller will restart/reload units as needed.
// * Disable the updateKubeConfigPermission() function.
func (dn *Daemon) updateInDeviceAgentMode(oldConfig, newConfig *mcfgv1.MachineConfig, skipCertificateWrite bool) (rebootRequired bool, retErr error) {
	oldConfig = canonicalizeEmptyMC(oldConfig)

	if dn.nodeWriter != nil {
		state, err := getNodeAnnotationExt(dn.node, constants.MachineConfigDaemonStateAnnotationKey, true)
		if err != nil {
			return false, err
		}
		if state != constants.MachineConfigDaemonStateDegraded && state != constants.MachineConfigDaemonStateUnreconcilable {
			if err := dn.nodeWriter.SetWorking(); err != nil {
				return false, fmt.Errorf("error setting node's state to Working: %w", err)
			}
		}
	}

	dn.catchIgnoreSIGTERM()
	defer func() {
		// now that we do rebootless updates, we need to turn off our SIGTERM protection
		// regardless of how we leave the "update loop"
		dn.cancelSIGTERM()
	}()

	oldConfigName := oldConfig.GetName()
	newConfigName := newConfig.GetName()

	oldIgnConfig, err := ctrlcommon.ParseAndConvertConfig(oldConfig.Spec.Config.Raw)
	if err != nil {
		return false, fmt.Errorf("parsing old Ignition config failed: %w", err)
	}
	newIgnConfig, err := ctrlcommon.ParseAndConvertConfig(newConfig.Spec.Config.Raw)
	if err != nil {
		return false, fmt.Errorf("parsing new Ignition config failed: %w", err)
	}

	klog.Infof("Checking Reconcilable for config %v to %v", oldConfigName, newConfigName)

	// make sure we can actually reconcile this state
	diff, reconcilableError := reconcilable(oldConfig, newConfig)
	diff.units = false

	if reconcilableError != nil {
		wrappedErr := fmt.Errorf("can't reconcile config %s with %s: %w", oldConfigName, newConfigName, reconcilableError)
		if dn.nodeWriter != nil {
			dn.nodeWriter.Eventf(corev1.EventTypeWarning, "FailedToReconcile", wrappedErr.Error())
		}
		return false, &unreconcilableErr{wrappedErr}
	}

	logSystem("Starting update from %s to %s: %+v", oldConfigName, newConfigName, diff)

	diffFileSet := ctrlcommon.CalculateConfigFileDiffs(&oldIgnConfig, &newIgnConfig)
	actions, err := calculatePostConfigChangeAction(diff, diffFileSet)
	if err != nil {
		return false, err
	}
	actions = []string{postConfigChangeActionNone}

	// Check and perform node drain if required
	drain, err := isDrainRequired(actions, diffFileSet, oldIgnConfig, newIgnConfig)
	if err != nil {
		return false, err
	}
	if drain {
		if err := dn.performDrain(); err != nil {
			return false, err
		}
	} else {
		klog.Info("Changes do not require drain, skipping.")
	}

	// update files on disk that need updating
	if err := dn.updateFiles(oldIgnConfig, newIgnConfig, skipCertificateWrite); err != nil {
		return false, err
	}

	defer func() {
		if retErr != nil {
			if err := dn.updateFiles(newIgnConfig, oldIgnConfig, skipCertificateWrite); err != nil {
				errs := kubeErrs.NewAggregate([]error{err, retErr})
				retErr = fmt.Errorf("error rolling back files writes: %w", errs)
				return
			}
		}
	}()

	// update file permissions
	// if err := dn.updateKubeConfigPermission(); err != nil {
	// 	return false, false, err
	// }

	// only update passwd if it has changed (do not nullify)
	// we do not need to include SetPasswordHash in this, since only updateSSHKeys has issues on firstboot.
	if diff.passwd {
		if err := dn.updateSSHKeys(newIgnConfig.Passwd.Users, oldIgnConfig.Passwd.Users); err != nil {
			return false, err
		}

		defer func() {
			if retErr != nil {
				if err := dn.updateSSHKeys(newIgnConfig.Passwd.Users, oldIgnConfig.Passwd.Users); err != nil {
					errs := kubeErrs.NewAggregate([]error{err, retErr})
					retErr = fmt.Errorf("error rolling back SSH keys updates: %w", errs)
					return
				}
			}
		}()
	}

	// Set password hash
	if err := dn.SetPasswordHash(newIgnConfig.Passwd.Users, oldIgnConfig.Passwd.Users); err != nil {
		return false, err
	}

	defer func() {
		if retErr != nil {
			if err := dn.SetPasswordHash(newIgnConfig.Passwd.Users, oldIgnConfig.Passwd.Users); err != nil {
				errs := kubeErrs.NewAggregate([]error{err, retErr})
				retErr = fmt.Errorf("error rolling back password hash updates: %w", errs)
				return
			}
		}
	}()

	if dn.os.IsCoreOSVariant() {
		coreOSDaemon := CoreOSDaemon{dn}
		if err := coreOSDaemon.applyOSChanges(*diff, oldConfig, newConfig); err != nil {
			return false, err
		}

		defer func() {
			if retErr != nil {
				if err := coreOSDaemon.applyOSChanges(*diff, newConfig, oldConfig); err != nil {
					errs := kubeErrs.NewAggregate([]error{err, retErr})
					retErr = fmt.Errorf("error rolling back changes to OS: %w", errs)
					return
				}
			}
		}()
	} else {
		klog.Info("updating the OS on non-CoreOS nodes is not supported")
	}

	// Ideally we would want to update kernelArguments only via MachineConfigs.
	// We are keeping this to maintain compatibility and OKD requirement.
	if err := UpdateTuningArgs(KernelTuningFile, CmdLineFile); err != nil {
		return false, err
	}

	// At this point, we write the now expected to be "current" config to /etc.
	// When we reboot, we'll find this file and validate that we're in this state,
	// and that completes an update.
	odc := &onDiskConfig{
		currentConfig: newConfig,
	}

	if err := dn.storeCurrentConfigOnDisk(odc); err != nil {
		return false, err
	}
	defer func() {
		if retErr != nil {
			odc.currentConfig = oldConfig
			if err := dn.storeCurrentConfigOnDisk(odc); err != nil {
				errs := kubeErrs.NewAggregate([]error{err, retErr})
				retErr = fmt.Errorf("error rolling back current config on disk: %w", errs)
				return
			}
		}
	}()

	return rebootRequired, dn.performPostConfigChangeAction(actions, newConfig.GetName())
}

// Export a few useful functions

func (dn *Daemon) Reboot(rationale string) error {
	return dn.reboot(rationale)
}

func RunCmdSync(cmdName string, args ...string) error {
	return runCmdSync(cmdName, args...)
}

func LogSystem(format string, a ...interface{}) {
	logSystem(format, a)
}
