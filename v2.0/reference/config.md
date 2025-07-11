---
title: "Config"
---


Config defines the v1alpha1.Config Talos machine configuration document.

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`version` |string |Indicates the schema used to decode the contents.  |`v1alpha1` |
|`debug` |bool |Enable verbose logging to the console. All system containers logs will flow into serial console. **Note:** To avoid breaking Talos bootstrap flow enable this option only if serial console can handle high message throughput.  |`true`, `yes`, `false`, `no` |
|`machine` |[MachineConfig](#machine) |Provides machine specific configuration options.  | |
|`cluster` |[ClusterConfig](#cluster) |Provides cluster specific configuration options.  | |

## machine

MachineConfig represents the machine-specific config values.

```yaml
machine:
    type: controlplane
    # InstallConfig represents the installation options for preparing a node.
    install:
        disk: /dev/sda # The disk used for installations.
        # Allows for supplying extra kernel args via the bootloader.
        extraKernelArgs:
            - console=ttyS1
            - panic=10
        image: ghcr.io/siderolabs/installer:latest # Allows for supplying the image used to perform the installation.
        wipe: false # Indicates if the installation disk should be wiped at installation time.

        # # Look up disk using disk attributes like model, size, serial and others.
        # diskSelector:
        #     size: 4GB # Disk size.
        #     model: WDC* # Disk model `/sys/block/<dev>/device/model`.
        #     busPath: /pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0 # Disk bus path.
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`type` |string |Defines the role of the machine within the cluster. **Control Plane** - Control Plane node type designates the node as a control plane member. This means it will host etcd along with the Kubernetes controlplane components such as API Server, Controller Manager, Scheduler. **Worker** - Worker node type designates the node as a worker node. This means it will be an available compute node for scheduling workloads. This node type was previously known as "join"; that value is still supported but deprecated.  |`controlplane`, `worker` |
|`token` |string |The `token` is used by a machine to join the PKI of the cluster. Using this token, a machine will create a certificate signing request (CSR), and request a certificate that will be used as its' identity. Example: `token: 328hom.uqjzh6jnn2eie9oi` | |
|`ca` |PEMEncodedCertificateAndKey |The root certificate authority of the PKI. It is composed of a base64 encoded `crt` and `key`. Example: `ca: {crt: LS0tIEVYQU1QTEUgQ0VSVElGSUNBVEUgLS0t, key: LS0tIEVYQU1QTEUgS0VZIC0tLQ==}` | |
|`acceptedCAs` |[]PEMEncodedCertificate |The certificates issued by certificate authorities are accepted in addition to issuing 'ca'. It is composed of a base64 encoded `crt`.  | |
|`certSANs` |[]string |Extra certificate subject alternative names for the machine's certificate. By default, all non-loopback interface IPs are automatically added to the certificate's SANs. Example: `certSANs: [10.0.0.10, 172.16.0.10, 192.168.0.10]` | |
|`controlPlane` |[MachineControlPlaneConfig](#controlplane) |Provides machine specific control plane configuration options. | |
|`kubelet` |[KubeletConfig](#kubelet) |Used to provide additional options to the kubelet. | |
|`pods` |[]Unstructured |Used to provide static pod definitions to be run by the kubelet directly bypassing the kube-apiserver. Static pods can be used to run components which should be started before the Kubernetes control plane is up. Talos doesn't validate the pod definition. Updates to this field can be applied without a reboot. See https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/. | |
|`network` |[NetworkConfig](#network) |Provides machine specific network configuration options. | |
|`install` |[InstallConfig](#install) |Used to provide instructions for installations. Note that this configuration section gets silently ignored by Talos images that are considered pre-installed. To make sure Talos installs according to the provided configuration, Talos should be booted with ISO or PXE-booted. | |
|`files` |[]MachineFile |Allows the addition of user specified files. The value of `op` can be `create`, `overwrite`, or `append`. In the case of `create`, `path` must not exist. In the case of `overwrite`, and `append`, `path` must be a valid file. If an `op` value of `append` is used, the existing file will be appended. Note that the file contents are not required to be base64 encoded. | |
|`env` |Env |The `env` field allows for the addition of environment variables. All environment variables are set on PID 1 in addition to every service. |`GRPC_GO_LOG_VERBOSITY_LEVEL`, `GRPC_GO_LOG_SEVERITY_LEVEL`, `http_proxy`, `https_proxy`, `no_proxy` |
|`time` |[TimeConfig](#time) |Used to configure the machine's time settings. | |
|`sysctls` |map[string]string |Used to configure the machine's sysctls. | |
|`sysfs` |map[string]string |Used to configure the machine's sysfs. | |
|`registries` |[RegistriesConfig](#registries) |Used to configure the machine's container image registry mirrors. Automatically generates matching CRI configuration for registry mirrors. The `mirrors` section allows to redirect requests for images to a non-default registry, which might be a local registry or a caching mirror. The `config` section provides a way to authenticate to the registry with TLS client identity, provide registry CA, or authentication information. Authentication information has same meaning with the corresponding field in [`.docker/config.json`](https://docs.docker.com/engine/api/v1.41/#section/Authentication). See also matching configuration for [CRI containerd plugin](https://github.com/containerd/cri/blob/master/docs/registry.md). | |
|`systemDiskEncryption` |[SystemDiskEncryptionConfig](#systemdiskencryption) |Machine system disk encryption configuration. Defines each system partition encryption parameters. | |
|`features` |[FeaturesConfig](#features) |Features describe individual Talos features that can be switched on or off. | |
|`udev` |[UdevConfig](#udev) |Configures the udev system. | |
|`logging` |[LoggingConfig](#logging) |Configures the logging system. | |
|`kernel` |[KernelConfig](#kernel) |Configures the kernel. | |
|`seccompProfiles` |[]MachineSeccompProfile |Configures the seccomp profiles for the machine. | |
|`baseRuntimeSpecOverrides` |Unstructured |Override (patch) settings in the default OCI runtime spec for CRI containers. It can be used to set some default container settings which are not configurable in Kubernetes, for example default ulimits. Note: this change applies to all newly created containers, and it requires a reboot to take effect. | |
|`nodeLabels` |map[string]string |Configures the node labels for the machine. Note: In the default Kubernetes configuration, worker nodes are restricted to set labels with some prefixes (see [NodeRestriction](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction) admission plugin). | |
|`nodeAnnotations` |map[string]string |Configures the node annotations for the machine. | |
|`nodeTaints` |map[string]string |Configures the node taints for the machine. Effect is optional. Note: In the default Kubernetes configuration, worker nodes are not allowed to modify the taints (see [NodeRestriction](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction) admission plugin). | |

### controlPlane

MachineControlPlaneConfig machine specific configuration options.

```yaml
machine:
    controlPlane:
        # Controller manager machine specific configuration options.
        controllerManager:
            disabled: false # Disable kube-controller-manager on the node.
        # Scheduler machine specific configuration options.
        scheduler:
            disabled: true # Disable kube-scheduler on the node.
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`controllerManager` |MachineControllerManagerConfig |Controller manager machine specific configuration options.  | |
|`scheduler` |MachineSchedulerConfig |Scheduler machine specific configuration options.  | |

#### controllerManager

MachineControllerManagerConfig represents the machine specific ControllerManager config values.

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`disabled` |bool |Disable kube-controller-manager on the node.  | |

#### scheduler

MachineSchedulerConfig represents the machine specific Scheduler config values.

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`disabled` |bool |Disable kube-scheduler on the node.  | |

### kubelet

KubeletConfig represents the kubelet config values.

```yaml
machine:
    kubelet:
        image: ghcr.io/siderolabs/kubelet:v1.33.0 # The `image` field is an optional reference to an alternative kubelet image.
        # The `extraArgs` field is used to provide additional flags to the kubelet.
        extraArgs:
            feature-gates: ServerSideApply=true

        # # The `ClusterDNS` field is an optional reference to an alternative kubelet clusterDNS ip list.
        # clusterDNS:
        #     - 10.96.0.10
        #     - 169.254.2.53

        # # The `extraMounts` field is used to add additional mounts to the kubelet container.
        # extraMounts:
        #     - destination: /var/lib/example # Destination is the absolute path where the mount will be placed in the container.
        #       type: bind # Type specifies the mount kind.
        #       source: /var/lib/example # Source specifies the source path of the mount.
        #       # Options are fstab style mount options.
        #       options:
        #         - bind
        #         - rshared
        #         - rw

        # # The `extraConfig` field is used to provide kubelet configuration overrides.
        # extraConfig:
        #     serverTLSBootstrap: true

        # # The `KubeletCredentialProviderConfig` field is used to provide kubelet credential configuration.
        # credentialProviderConfig:
        #     apiVersion: kubelet.config.k8s.io/v1
        #     kind: CredentialProviderConfig
        #     providers:
        #         - apiVersion: credentialprovider.kubelet.k8s.io/v1
        #           defaultCacheDuration: 12h
        #           matchImages:
        #             - '*.dkr.ecr.*.amazonaws.com'
        #             - '*.dkr.ecr.*.amazonaws.com.cn'
        #             - '*.dkr.ecr-fips.*.amazonaws.com'
        #             - '*.dkr.ecr.us-iso-east-1.c2s.ic.gov'
        #             - '*.dkr.ecr.us-isob-east-1.sc2s.sgov.gov'
        #           name: ecr-credential-provider

        # # The `nodeIP` field is used to configure `--node-ip` flag for the kubelet.
        # nodeIP:
        #     # The `validSubnets` field configures the networks to pick kubelet node IP from.
        #     validSubnets:
        #         - 10.0.0.0/8
        #         - '!10.0.0.3/32'
        #         - fdc7::/16
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`image` |string |The `image` field is an optional reference to an alternative kubelet image. Example: `image: ghcr.io/siderolabs/kubelet:v1.33.0` | |
|`clusterDNS` |[]string |The `ClusterDNS` field is an optional reference to an alternative kubelet clusterDNS ip list. Example: `clusterDNS: [10.96.0.10, 169.254.2.53]` | |
|`extraArgs` |map[string]string |The `extraArgs` field is used to provide additional flags to the kubelet. Example: `extraArgs: {key: value}` | |
|`extraMounts` |[]ExtraMount |The `extraMounts` field is used to add additional mounts to the kubelet container. Note that either `bind` or `rbind` are required in the `options`. | |
|`extraConfig` |Unstructured |The `extraConfig` field is used to provide kubelet configuration overrides. Some fields are not allowed to be overridden: authentication and authorization, cgroups configuration, ports, etc. Example: `extraConfig: {serverTLSBootstrap: true}` | |
|`credentialProviderConfig` |Unstructured |The `KubeletCredentialProviderConfig` field is used to provide kubelet credential configuration. | |
|`defaultRuntimeSeccompProfileEnabled` |bool |Enable container runtime default Seccomp profile.  |`true`, `yes`, `false`, `no` |
|`registerWithFQDN` |bool |The `registerWithFQDN` field is used to force kubelet to use the node FQDN for registration. This is required in clouds like AWS.  |`true`, `yes`, `false`, `no` |
|`nodeIP` |KubeletNodeIPConfig |The `nodeIP` field is used to configure `--node-ip` flag for the kubelet. This is used when a node has multiple addresses to choose from. | |
|`skipNodeRegistration` |bool |The `skipNodeRegistration` is used to run the kubelet without registering with the apiserver. This runs kubelet as standalone and only runs static pods.  |`true`, `yes`, `false`, `no` |
|`disableManifestsDirectory` |bool |The `disableManifestsDirectory` field configures the kubelet to get static pod manifests from the /etc/kubernetes/manifests directory. It's recommended to configure static pods with the "pods" key instead.  |`true`, `yes`, `false`, `no` |

### network

NetworkConfig represents the machine's networking config values.

```yaml
machine:
    network:
        hostname: worker-1 # Used to statically set the hostname for the machine.
        # `interfaces` is used to define the network interface configuration.
        interfaces:
            - interface: enp0s1 # The interface name.
              # Assigns static IP addresses to the interface.
              addresses:
                - 192.168.2.0/24
              # A list of routes associated with the interface.
              routes:
                - network: 0.0.0.0/0 # The route's network (destination).
                  gateway: 192.168.2.1 # The route's gateway (if empty, creates link scope route).
                  metric: 1024 # The optional metric for the route.
              mtu: 1500 # The interface's MTU.
        # Used to statically set the nameservers for the machine.
        nameservers:
            - 9.8.7.6
            - 8.7.6.5
        # Used to statically set arbitrary search domains.
        searchDomains:
            - example.org
            - example.com
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`hostname` |string |Used to statically set the hostname for the machine.  | |
|`interfaces` |[]Device |`interfaces` is used to define the network interface configuration. By default all network interfaces will attempt a DHCP discovery. This can be further tuned through this configuration parameter. | |
|`nameservers` |[]string |Used to statically set the nameservers for the machine. Defaults to `1.1.1.1` and `8.8.8.8` Example: `nameservers: [8.8.8.8, 1.1.1.1]` | |
|`searchDomains` |[]string |Used to statically set arbitrary search domains. Example: `searchDomains: [example.org, example.com]` | |
|`extraHostEntries` |[]ExtraHost |Allows for extra entries to be added to the `/etc/hosts` file | |
|`kubespan` |NetworkKubeSpan |Configures KubeSpan feature. Example: `kubespan: {enabled: true}` | |
|`disableSearchDomain` |bool |Disable generating a default search domain in /etc/resolv.conf based on the machine hostname. Defaults to `false`.  |`true`, `yes`, `false`, `no` |

### install

InstallConfig represents the installation options for preparing a node.

```yaml
machine:
    install:
        disk: /dev/sda # The disk used for installations.
        # Allows for supplying extra kernel args via the bootloader.
        extraKernelArgs:
            - console=ttyS1
            - panic=10
        image: ghcr.io/siderolabs/installer:latest # Allows for supplying the image used to perform the installation.
        wipe: false # Indicates if the installation disk should be wiped at installation time.

        # # Look up disk using disk attributes like model, size, serial and others.
        # diskSelector:
        #     size: 4GB # Disk size.
        #     model: WDC* # Disk model `/sys/block/<dev>/device/model`.
        #     busPath: /pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0 # Disk bus path.
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`disk` |string |The disk used for installations. Examples: `disk: /dev/sda`, `disk: /dev/nvme0` | |
|`diskSelector` |InstallDiskSelector |Look up disk using disk attributes like model, size, serial and others. Always has priority over `disk`. | |
|`extraKernelArgs` |[]string |Allows for supplying extra kernel args via the bootloader. Existing kernel args can be removed by prefixing the argument with a `-`. For example `-console` removes all `console=<value>` arguments, whereas `-console=tty0` removes the `console=tty0` default argument. If Talos is using systemd-boot as a bootloader (default for UEFI) this setting will be ignored. Example: `extraKernelArgs: [talos.platform=metal, reboot=k]` | |
|`image` |string |Allows for supplying the image used to perform the installation. Image reference for each Talos release can be found on [GitHub releases page](https://github.com/siderolabs/talos/releases). Example: `image: ghcr.io/siderolabs/installer:latest` | |
|`wipe` |bool |Indicates if the installation disk should be wiped at installation time. Defaults to `true`.  |`true`, `yes`, `false`, `no` |
|`legacyBIOSSupport` |bool |Indicates if MBR partition should be marked as bootable (active). Should be enabled only for the systems with legacy BIOS that doesn't support GPT partitioning scheme. | |

### time

TimeConfig represents the options for configuring time on a machine.

```yaml
machine:
    time:
        disabled: false # Indicates if the time service is disabled for the machine.
        # description: |
        servers:
            - time.cloudflare.com
        bootTimeout: 2m0s # Specifies the timeout when the node time is considered to be in sync unlocking the boot sequence.
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`disabled` |bool |Indicates if the time service is disabled for the machine. Defaults to `false`. | |
|`servers` |[]string |Specifies time (NTP) servers to use for setting the system time. Defaults to `time.cloudflare.com`. Talos can also sync to the PTP time source (e.g provided by the hypervisor), provide the path to the PTP device as "/dev/ptp0" or "/dev/ptp_kvm". | |
|`bootTimeout` |Duration |Specifies the timeout when the node time is considered to be in sync unlocking the boot sequence. NTP sync will be still running in the background. Defaults to "infinity" (waiting forever for time sync) | |

### registries

RegistriesConfig represents the image pull options.

```yaml
machine:
    registries:
        # Specifies mirror configuration for each registry host namespace.
        mirrors:
            docker.io:
                # List of endpoints (URLs) for registry mirrors to use.
                endpoints:
                    - https://registry.local
        # Specifies TLS & auth configuration for HTTPS image registries.
        config:
            registry.local:
                # The TLS configuration for the registry.
                tls:
                    # Enable mutual TLS authentication with the registry.
                    clientIdentity:
                        crt: LS0tIEVYQU1QTEUgQ0VSVElGSUNBVEUgLS0t
                        key: LS0tIEVYQU1QTEUgS0VZIC0tLQ==
                # The auth configuration for this registry.
                auth:
                    username: username # Optional registry authentication.
                    password: password # Optional registry authentication.
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`mirrors` |map[string]RegistryMirrorConfig |Specifies mirror configuration for each registry host namespace. This setting allows to configure local pull-through caching registires, air-gapped installations, etc. For example, when pulling an image with the reference `example.com:123/image:v1`, the `example.com:123` key will be used to lookup the mirror configuration. Optionally the `*` key can be used to configure a fallback mirror. Registry name is the first segment of image identifier, with 'docker.io' being default one. | |
|`config` |map[string]RegistryConfig |Specifies TLS & auth configuration for HTTPS image registries. Mutual TLS can be enabled with 'clientIdentity' option. The full hostname and port (if not using a default port 443) should be used as the key. The fallback key `*` can't be used for TLS configuration. TLS configuration can be skipped if registry has trusted server certificate. | |

### systemDiskEncryption

SystemDiskEncryptionConfig specifies system disk partitions encryption settings.

```yaml
machine:
    systemDiskEncryption:
        # Ephemeral partition encryption.
        ephemeral:
            provider: luks2 # Encryption provider to use for the encryption.
            # Defines the encryption keys generation and storage method.
            keys:
                - # Deterministically generated key from the node UUID and PartitionLabel.
                  nodeID: {}
                  slot: 0 # Key slot number for LUKS2 encryption.

                  # # KMS managed encryption key.
                  # kms:
                  #     endpoint: https://192.168.88.21:4443 # KMS endpoint to Seal/Unseal the key.

            # # Cipher kind to use for the encryption. Depends on the encryption provider.
            # cipher: aes-xts-plain64

            # # Defines the encryption sector size.
            # blockSize: 4096

            # # Additional --perf parameters for the LUKS2 encryption.
            # options:
            #     - no_read_workqueue
            #     - no_write_workqueue
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`state` |EncryptionConfig |State partition encryption.  | |
|`ephemeral` |EncryptionConfig |Ephemeral partition encryption.  | |

### features

FeaturesConfig describes individual Talos features that can be switched on or off.

```yaml
machine:
    features:
        rbac: true # Enable role-based access control (RBAC).

        # # Configure Talos API access from Kubernetes pods.
        # kubernetesTalosAPIAccess:
        #     enabled: true # Enable Talos API access from Kubernetes pods.
        #     # The list of Talos API roles which can be granted for access from Kubernetes pods.
        #     allowedRoles:
        #         - os:reader
        #     # The list of Kubernetes namespaces Talos API access is available from.
        #     allowedKubernetesNamespaces:
        #         - kube-system
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`rbac` |bool |Enable role-based access control (RBAC).  | |
|`stableHostname` |bool |Enable stable default hostname.  | |
|`kubernetesTalosAPIAccess` |KubernetesTalosAPIAccessConfig |Configure Talos API access from Kubernetes pods. This feature is disabled if the feature config is not specified. | |
|`apidCheckExtKeyUsage` |bool |Enable checks for extended key usage of client certificates in apid.  | |
|`diskQuotaSupport` |bool |Enable XFS project quota support for EPHEMERAL partition and user disks. Also enables kubelet tracking of ephemeral disk usage in the kubelet via quota.  | |
|`kubePrism` |KubePrism |KubePrism - local proxy/load balancer on defined port that will distribute requests to all API servers in the cluster.  | |
|`hostDNS` |HostDNSConfig |Configures host DNS caching resolver.  | |
|`imageCache` |ImageCacheConfig |Enable Image Cache feature.  | |
|`nodeAddressSortAlgorithm` |string |Select the node address sort algorithm. The 'v1' algorithm sorts addresses by the address itself. The 'v2' algorithm prefers more specific prefixes. If unset, defaults to 'v1'.  | |

### udev

UdevConfig describes how the udev system should be configured.

```yaml
machine:
    udev:
        # List of udev rules to apply to the udev system
        rules:
            - SUBSYSTEM=="drm", KERNEL=="renderD*", GROUP="44", MODE="0660"
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`rules` |[]string |List of udev rules to apply to the udev system  | |

### logging

LoggingConfig struct configures Talos logging.

```yaml
machine:
    logging:
        # Logging destination.
        destinations:
            - endpoint: tcp://1.2.3.4:12345 # Where to send logs. Supported protocols are "tcp" and "udp".
              format: json_lines # Logs format.
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`destinations` |[]LoggingDestination |Logging destination.  | |

### kernel

KernelConfig struct configures Talos Linux kernel.

```yaml
machine:
    kernel:
        # Kernel modules to load.
        modules:
            - name: brtfs # Module name.
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`modules` |[]KernelModuleConfig |Kernel modules to load.  | |

## cluster

ClusterConfig represents the cluster-wide config values.

```yaml
cluster:
    # ControlPlaneConfig represents the control plane configuration options.
    controlPlane:
        endpoint: https://1.2.3.4 # Endpoint is the canonical controlplane endpoint, which can be an IP address or a DNS hostname.
        localAPIServerPort: 443 # The port that the API server listens on internally.
    clusterName: talos.local
    # ClusterNetworkConfig represents kube networking configuration options.
    network:
        # The CNI used.
        cni:
            name: flannel # Name of CNI to use.
        dnsDomain: cluster.local # The domain used by Kubernetes DNS.
        # The pod subnet CIDR.
        podSubnets:
            - 10.244.0.0/16
        # The service subnet CIDR.
        serviceSubnets:
            - 10.96.0.0/12
```

| Field | Type | Description | Value(s) |
|-------|------|-------------|----------|
|`id` |string |Globally unique identifier for this cluster (base64 encoded random 32 bytes).  | |
|`secret` |string |Shared secret of cluster (base64 encoded random 32 bytes). This secret is shared among cluster members but should never be sent over the network.  | |
|`controlPlane` |ControlPlaneConfig |Provides control plane specific configuration options. | |
|`clusterName` |string |Configures the cluster's name.  | |
|`network` |ClusterNetworkConfig |Provides cluster specific network configuration options. | |
|`token` |string |The [bootstrap token](https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/) used to join the cluster. Example: `token: wlzjyw.bei2zfylhs2by0wd` | |
|`aescbcEncryptionSecret` |string |A key used for the [encryption of secret data at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/). Enables encryption with AESCBC. Example: `aescbcEncryptionSecret: z01mye6j16bspJYtTB/5SFX8j7Ph4JXxM2Xuu4vsBPM=` | |
|`secretboxEncryptionSecret` |string |A key used for the [encryption of secret data at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/). Enables encryption with secretbox. Secretbox has precedence over AESCBC. Example: `secretboxEncryptionSecret: z01mye6j16bspJYtTB/5SFX8j7Ph4JXxM2Xuu4vsBPM=` | |
|`ca` |PEMEncodedCertificateAndKey |The base64 encoded root certificate authority used by Kubernetes. | |
|`acceptedCAs` |[]PEMEncodedCertificate |The list of base64 encoded accepted certificate authorities used by Kubernetes.  | |
|`aggregatorCA` |PEMEncodedCertificateAndKey |The base64 encoded aggregator certificate authority used by Kubernetes for front-proxy certificate generation. This CA can be self-signed. | |
|`serviceAccount` |PEMEncodedKey |The base64 encoded private key for service account token generation. | |
|`apiServer` |APIServerConfig |API server specific configuration options. | |
|`controllerManager` |ControllerManagerConfig |Controller manager server specific configuration options. | |
|`proxy` |ProxyConfig |Kube-proxy server-specific configuration options | |
|`scheduler` |SchedulerConfig |Scheduler server specific configuration options. | |
|`discovery` |ClusterDiscoveryConfig |Configures cluster member discovery. | |
|`etcd` |Et