# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Calendar Versioning](https://calver.org/).

## [26.8.0] - 2026-08-15

### Features

- Introducing In-Browser Web Terminal. Access your SSH shell directly from the EDH Web Interface
- Introducing real-time file streaming via the EDH Web Interface
- Introducing EDH AI Assistant. Chat with the AI Assistant through the EDH Website or use the Python SDK
- Introducing Virtual Desktop Session Sharing. Invite guest to collaborate with your own level of permissions on your VDI
- Introducing Resource Mirroring. Optionally copy any required third-party library into your own S3 bucket
- Introducing EDH Translation Framework (12 languages)
- Introducing My HPC Jobs explorer with client-rendered table/timeline (Gantt) views, quick search, advanced filters, sortable columns, and job provisioning/error status indicators
- Introducing Auto-Managed Prefix Lists with dual-stack IPv6 support for networking
- (Preview) Introducing Scoped API Tokens (`edh_` prefix), a better way to manage API access with path/method-based permissions, global deny rules, per-token allow/deny, and a full web-based Token Audit interface
- (Preview) Introducing DCV Image Accelerator (Base Image Acceleration). Automatically copy and maintain owned-base AMIs in your account with priority ordering and a Local Acceleration Mirror status UI
- (Preview) Introducing Saved Desktops. Save & Shut Down your VDI, resume later from a captured AMI with warm-resume bootstrap wiring and Spot interruption auto-capture
- (Preview) Introducing Spot Instance support for Virtual Desktops.
- (Preview) Hardware Profile for DCV USB remotization management.
- Added CDK synth-time token-leak guard aspect to catch unresolved tokens at build time
- Added GPU driver version sourcing from configuration (no longer hardcoded)
- Added VDI launch template IPv6 support and resource-name AAAA DNS records
- Added dual-stack DCV NLBs and IPv6 backend fabric

### Changed

- `/api/login_nodes/list` now returns a list of EC2 Instances (previously only a list of Public or Private IP addresses)
- Updated AWS EFA Installer from `1.47.0` to `1.48.0`
- You can now see machine screenshots for your VDI. A privacy masking feature is also implemented to blur the thumbnails.
- You can now use an existing HTTPS certificate when installing EDH
- EDH Virtual Desktop has now migrated to DCV Session Manager and DCV Broker
- My HPC Jobs now displays finished jobs with start/end times, duration, and job state badges
- HPC Job visibility scope is now configurable (`all`, `project`, `owner_only`) with a configurable default time window and max row limit
- Token size and complexity increased for improved security
- File Transfer engine is now configurable (`v1` or `v2`) via `FileBrowser/TransferEngine` setting (v2 is considered Preview mode for this release)
- Resource mirroring now defaults to in-VPC Lambda execution
- Base image copy priority now uses architecture-keyed base_os lists (JSON format)
- Multiprocess-safe log rotation under uwsgi
- Web shell now supports mouse-wheel scrollback with native browser copy
- `/etc/environment` variables auto-exported with `set -a` instead of `export`

### Fixes

- Fixed launching EFA-enabled jobs on `hpc6id` instance family
- Improved compatibility for multi-card (multi-rail) EFA instances
- Fixed HPC job names sanitization and CRLF normalization at render time
- Fixed custom tags being read from the correct seeded config path
- Fixed CDK token leak: log construct IDs instead of unresolved CDK tokens
- Fixed tus uploads now rejected when exceeding declared Upload-Length
- Fixed DCV broker server resolution by live IMDS instance-id
- Fixed DCV OS icon, NoneType thumbnail, and atomic capture idempotency
- Fixed ConfigSync sentinel only stamped on full-cluster walk
- Fixed BackupSelection dependency on backup role inline policy
- Fixed TargetNode egress set to allow_all_outbound
- Fixed installer clear dup-stack error and cluster/region-scope staging
- Fixed public session-state and pricing endpoints now auth-gated
- Fixed always-on capacity provisioning failing to launch when an existing On-Demand Capacity Reservation (ODCR) was specified
- Fixed password policy PSO not being applied to any users/groups (`msDS-PSOAppliesTo` was never set); now linked to configurable group(s), default `Domain Users`
- Fixed job cost estimator returning "Unable to estimate cost" for instance types with no Reserved Instance price; now falls back to the on-demand rate (flagged in the UI)
- Security: symlink-safe home directory provisioning
- Security: HPC job script created with `O_EXCL` to block symlink write
- Target Node User Data and Workflow Job Script templates are now validated by Jinja before creation.

## [26.4.0] - 2026-04-16

Project name has been updated to Engineering Development Hub (EDH)

### Features

- The `SOCA/EDH` Web Interface has undergone an overhaul to modernize the look and feel. Please let us know what you think!
- SOCA/EDH Now supports the AWS European Sovereign Cloud (EUSC)
  - For more information https://aws.amazon.com/blogs/aws/opening-the-aws-european-sovereign-cloud/
- Users can now automatically deactivate (enabled by default) the AD 42 days password expiration when deploying AWS Directory Service Managed AD
- Users can now decide to enable/disable Nested Virtualization on their EC2 machines

### Changed

- `X-SOCA-TOKEN` / `X-SOCA-USER` / `X-SOCA-PASSWORD` has been renamed `X-EDH-TOKEN` / `X-EDH-USER` / `X-EDH-PASSWORD`
- AWS tag prefix has been updated to `edh:` from `soca:`
- When viewing the API key in the WebUI - the API key is now blurred by default.
- When viewing the details of a job from the `My Jobs` screen, the auto-refresh will now disable to avoid a refresh while reviewing the job details.

### Fixes

- Improvements have been made for Active Directory..
- When using a timezone other than UTC on the SOCA Controller, users may encounter a failure to launch VDIs due to an error in capacity validation.
- Fixed a SSH passwordless configuration when using Target Nodes user data
- Removed hardcoded EBS root device name based on OS distro. Value is now automatically detected via AWS APIs.

### Known Issues

- N/A

## [26.3.1] - 2026-03-20

### Features

- _No new features in this release. Bug fixes only._

### Changed

- _No new changes in this release. Bug fixes only._

### Fixes

- When using a timezone other than UTC on the SOCA Controller, users may encounter a failure to launch VDIs due to an error in capacity validation.
- During WebUI submission of HPC jobs, in some situations, the CPU/vCPU calculations may be incorrect causing problems with job launches due to incorrect number of nodes or CPUs.
- An incorrect directory name was generated for portions of the OpenPBS scheduler installation.
-

## Known Issues

## [26.3.0] - 2026-03-06

### Features

- You can now attach your Virtual Desktop request to existing Capacity Reservation ID created outside of SOCA (either Capacity Reservation of ML Capacity Block)
- You can now attach your HPC job request to existing Capacity Reservation ID created outside of SOCA (either Capacity Reservation of ML Capacity Block)
- Adding support for `AlwaysOn` nodes for multi-schedulers (LSF and OpenPBS)
- Preview support for Altair PBSPro
- Added support for Image Alias when registering a VDI Software Stacks
  - This improves the default SOCA installation by not having the Windows AMIs expire after 90-days
  - For more information - https://docs.aws.amazon.com/ec2/latest/windows-ami-reference/windows-ami-versions.html and https://aws.amazon.com/blogs/mt/query-for-the-latest-windows-ami-using-systems-manager-parameter-store/
- `orchestrator` transparent migration is now complete and is now the default capacity management mode. You can always use `legacy` mode if needed. Please note `legacy` mode is no longer supported and will be removed later this year.
- `instance_type` has been superseded by `instance_types` for HPC job attributes. While both are supported for now, please migrate to `instance_types` as `instance_type` will be deprecated in the future. This change is to standardize `SocaHpcJob` naming convention as SOCA accepts a list of instance types for each job.
- `subnet_id` has been superseded by `subnet_ids` for HPC job attributes. While both are supported for now, please migrate to `subnet_ids` as `subnet_id` will be deprecated in the future. This change is to standardize `SocaHpcJob` naming convention as SOCA accepts a list of subnet IDs for each job.
- Introduced enforced capacity verification ahead of VDI and HPC node provisioning by leveraging ephemeral capacity reservations to ensure all requested capacity can be fully provisioned.
- Support of Capacity Block for ML

### Changed

- `root` user cannot execute custom `bsub` on LSF. Job submission is enforced for LDAP users
- `SocaConfig` has been moved to `utils.config` from `utils.aws.ssm_parameter_store`
- `SocaSecret` has been moved to `utils.aws.secretsmanager_client.py` from `utils.aws.secrets_manager.py`
- Updated AWS Elasticache Engine Version from `7` to `8` for the Valkey engine.
- SOCA creates discrete log for each job id
- Added backoff support to `aws_cli` wrappers to prevent bootstrap failures when AWS APIs return throttling errors
- Bump Nvidia Grid Driver to `580.126.09` (from `570.172.08`)
- Added Lustre driver support for EL9 kernels `5.14.0-611*`
- Updated boto3 `1.40.16` to `1.42.29`
- Capacity provisioning stops after three failed attempts if a job cannot start
- Job Refresh Grace Time is now configurable (default to `30` minutes)
- Enable`gr6f` and `g7e` instance families by default for virtual desktops / VDI
- Updated AWS EFA Installer from `1.43.2` to `1.47.0`
- Updated DCV to `2024.0` to `2025.0`

### Fixes

- Fixed a bug that prevented installation in some environments with strict AWS SCPs that require 'tag-on-create'.
- Fixed IAM role permissions for certificate generation lambda not logging correctly.
- Fixed a bug that prevented `connection_string` to be updated on target nodes
- Fixed bootstrap code to support custom shell wrappers for multi-schedulers
- Fixed a bug that caused the OpenPBS compilation phase to use more CPUs than was active on the instance.
- Fixed an issue where `--client-ip` was incorrectly being cast as a list of array
- Updated MUNGE from `0.5.16` to `0.5.18` to address `CVE-2026-25506`

### Known Issues

- When submitting a high volume of `Rocky8`, `RHEL8`, or `Amazon Linux 2` jobs, external endpoints may impose rate limits that prevent successful downloads of `automake` and `libtool`. If this occurs, download `system.scheduler.openpbs.compatibility_packages.automake` and `system.scheduler.openpbs.compatibility_packages.libtool` to `/apps` or `/data`, then update `cluster_node_boostrap/templates/linux/scheduler/openpbs/install.sh.j2` accordingly. We are planning to implement a better way to handle external dependency in the upcoming releases.

## [25.11.0] - 2025-11-17

### Features

- Added support for `Asia Pacific (Taipei)` / `ap-east-2` to SOCA.
  - Not all BaseOSes are supported - check `region_map.d` for more information.
- Introducing smart subnet id selection for Virtual Desktops and Target Nodes provisioning. When enabled, SOCA will validate capacity availability and try other subnets automatically as needed.
- SOCA installation will now create a dedicated cluster SNS topic for important administrative events. The interactive installer now asks for the `E-mail address` for notifications.
- You can now add environment variables during EKS job submission
- Added ability to disable domain join for HPC ephemeral nodes
- Added `--email` command-line option to `soca_install.sh` to provide the notification E-mail address. Format can be `--email email1@example.com --email email2@example.com` or `--email email1@example.com,email2@example.com`.
- Improved VDI Idle detection by using `GPU` as well as `CPU` as a resource for idle detection
  - Supported on `NVIDIA` GPUs only at this release
- Preview support for IBM Spectrum LSF scheduler
- Preview support for SchedMD Slurm scheduler
- Preview support for new SOCA Automatic Host Provisioning (disabled by default)
- Preview support to optionally disable Active Directory domain join for ephemeral HPC compute nodes

### Changed

- Updated `SOCA Controller` default instance type to `m8i-flex.large` in regions where it is available.
- Updated `OpenSearch` default instance to `m7g.large.search` when SOCA is creating the OpenSearch/Analytics cluster.
- Removed support for `AWS Directory Service - Simple AD` as a back-end user Directory (disabled in previous releases).
- Increased the AD Join loop to 30 tries for slower AD environments or faster ephemeral nodes.
- Updated all BaseOS AMIs for all regions/partitions for more up to date AMIs.
- Continue deprecation of `CentOS 7` and removed `CentOS 7`
- Split the creation of `VPC Endpoints` between `interface` and `gateway`
  - Enable `gateway VPC Endpoints` by default
- Added CDK Strict enforcement by default. This can be disabled with `--cdk-no-strict` when running `soca_install.sh`
- Updated various Python modules
- Updated AWS EFA Installer to `1.43.2`
- Increased SocaLogger's rotating file size limit from 5MB to 50MB
- PBS Nodes are now registering using their private Ipv4 as MoM (previous AWS Private DNS, which could cause some problems when using custom non-AWS DNS)
- Updated missing API documentations for `VirtualDesktopProfilesManager`, `TargetNodeSoftwareStacksManager` and `GetVirtualDesktopsSessionState`
- RHEL9 updated from RHEL9.5 to RHEL9.6
- AL2023 updated from `2023.7` to `2023.9` kernel 6.1
- Updated OpenPBS installation via git to commit ID `2bf8f31fbd5bbd7fff4b1c620c625d2944b422b1`

### Fixes

- NVIDIA drivers are now installed correctly on Ubuntu `-aws` kernels
- Fixed TargetNode hibernation detection defect (seen during launch).
- Added automatic AZ selection for the `SOCA Controller` based on the selected `Instance Type`. Previously the first AZ in a region was always used but this may change based on AZ-availability of a selected instance type.
- Fixed bug that prevents tags to be propagated correctly when using FSx for Lustre

## [25.8.0] - 2025-08-05

### In Preview

Features in preview can be enabled in `default_config.yml` (or via `socactl` on running environment) via the new Feature Flags framework.
These features are not yet considered stable but are available for experimental use.

- Capacity Reservation support for Virtual Desktops.
- Introducing `SOCA Containers` management via Amazon Elastic Container Registry (ECR) and Elastic Kubernetes Services (EKS)

### Features

- Introducing `SOCA Target Nodes`: Manage any AWS AMI directly within SOCA with the ability to create custom User Data for each node
- Introducing `Feature Flags` and `Web User Personas`. Decide what Web Views and APIs you want to enable/disable per users
- SOCA Projects can now control visibility/access for Virtual Desktop Software Stacks, Target Nodes Software Stacks, and Application Profiles
- Added support for dynamic `CustomTags`. You can now add/remove your own tags to any resources deployed by SOCA
- AWS Budget can now be assigned to SOCA Projects.
- SOCA Installation using `Existing Resources` can now make use of existing `FSx/OpenZFS` during installation.
  - NOTE - The FSx/OpenZFS filesystem needs to be configured with the `no_root_squash` setting for the `controller` host or globally.
- Updated APIs spec to OpenAPI 3.1. Documentation is now available for Swagger and RapiDoc
- Added support for Fractional GPU instances (`g6f`)

### Changed

- Rework how default AMIs are specified between the SOCA revisions and how SOCA Administrators can maintain local configuration files of over-rides. See `installer/region_map.d/README.md` for more information.
- Endpoint for OpenLDAP now default to the private IP of the SOCA Controller instead of the DNS (handle case where instance has custom DNS)
- You can now add a description for your Virtual Desktop Profiles
- Added autocomplete capability for instance type list
- CustomTags are now propagated to Compute Nodes / VDI Nodes and Target Nodes
- Instance types are now sorted by generation (newest first) and size (largest first)
- Automatically install GPU driver on Windows 2025
- Updated NVIDIA GRID Driver from `18.1` to `18.4` for Linux VDI instances

### Fixes

- A javascript error prevented application profiles from being saved into the database properly. This would manifest as an empty application once it was saved.
- A filesystem permissions problem prevented users from navigating into newly created directories.

## [25.5.0] - 2025-05-13

### Features

- Amazon Linux 2023 can now be used as a Virtual Desktop node
- Updated Python environment from `3.9.21` from `3.13.2`
- You can now decide to configure `virtual` or `console` DCV sessions via the web interface

### Changed

- Updated RHEL9 version from `9.3` to `9.5`
- Updated Amazon Linux 2023 version from `2023.6` to `2023.7`
- Misc `pip` package updates

## [25.3.0] - 2025-03-31

### Features

- New Base OSes supported:
  - `Windows Server 2022` and `Windows Server 2025` for Windows VDI
  - Ubuntu `22.04 LTS` and Ubuntu `24.04 LTS` for Linux VDI and HPC compute nodes
- The SOCA ALB TLS policy can now be controlled in the configuration file (`default_config.yaml`) via `Config.network.alb_tls_policy`.
  - The policy defaults to `ELBSecurityPolicy-TLS13-1-2-2021-06` if not specified in the configuration. This allows for `TLS 1.3` and `TLS 1.2` _ONLY_.
  - If you have clients connecting with older versions of TLS / SSL, you will need to update this parameter\_
  - For a full list of TLS policy names and associated security protocols/ciphers allowed please consult the AWS Application Load Balancer [documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html)
- [AWS Global Accelerator](https://aws.amazon.com/global-accelerator/) is now supported for public-facing deployments
  - AWS Global Accelerator is disabled by default and can be enabled in the `default_config.yaml` by setting `Config.network.aws_aga.enabled` to `true`.

- SOCA Controller logic has been moved to a local partition `/opt/soca` for better performance and security. Boostrap logs are still available on `/apps/soca/`
- SSH access to the Controller host is now limited to SOCA admins
- Virtual Desktop interface has been revamped:
  - Introducing a brand-new web interface
  - Linux and Windows desktops can now be deployed in the same page
  - You can now edit a software stack
  - Introducing Virtual Desktop Profiles, giving you ability to limit the type of instance, storage, and subnets that can be used for your software stacks
  - SOCA admins can list all active virtual desktops
- Introducing SOCA Projects: a new way to control ACLs for Virtual Desktops
- Added integration to your [Amazon Q Business](https://aws.amazon.com/q/business/) application if specified

### Changed

- Misc HTML cleanups in the SOCA WebUI
- The Amazon Route 53 Resolver Endpoints for the directory service now make use of their own discrete Security Group. This security group allows for the SOCA cluster to interact with the Resolver as well as the VPC IP CIDR Range.

### Fixes

- A jsii Runtime error would be generated if the configuration for login nodes had a `desired_count` that was lower or higher than the `min_count`/`max_count`. This has been corrected.
- A jsii Runtime error would be generated if ElastiCache was disabled due to missing `node.add_dependency()`
- A jsii Runtime error would be generated if Analytics was disabled due to empty Parameter Store value
- The logged in username was missing from the analytics dashboard page. This has been fixed.
- Under certain circumstances the internal Python interpreter for the OpenPBS scheduler can fail to process hooks after an internal restart. This would cause any future hooks to fail until the service was restarted. The default restart interval for the internal Python interpreter has been updated to `9,999,999` jobs to fix this.
- Using the `Private` subnet entry mode during installation would generate an error and cause the installation to fail. This has been fixed. (Introduced in `24.10.0`)

## [25.1.0] - 2025-01-28

### Features

- Introduction of [SOCA Storage AutoMount](https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/storage/shared-storage/), a wrapper to simplify filesystems management
- Added support for FSx for NetApp ONTAP for /apps & /data partitions (including ACL and CIFS automatic setup)
- Added support for S3-Mountpoint (Mountpoint for Amazon S3 is a simple, high-throughput file client for mounting an Amazon S3 bucket as a local file system)
- Enabled [SOCA Easy AMI setup](https://awslabs.github.io/scale-out-computing-on-aws-documentation/tutorials/reduce-compute-node-launch-time-with-custom-ami/)
- Added `file_download` wrapper for [SOCA Node Boostrap customizations](https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/architecture/node-bootstrap/customize-node-boostrap/)

### Changed

**_IMPORTANT BASE OS CHANGES_**

- **NOTE** - This is part of a multi-release deprecation process for older/unsupported BaseOSes
- Continue to wind-down support for `CentOS 7`, `CentOS 8` and `RHEL 7` for new installations
  - You can enable installation to these BaseOSes with custom AMIs by manually adding AMIs to the proper sections in the `installer/region_map.yaml` file
  - Migration should take place ASAP if you are still using these unsupported releases

- Update `region_map.yaml` to include newer AWS regions / AMIs (not all BaseOSes are available in all regions)
- `SOCA_CONFIGURATION` environment variable has been renamed to `SOCA_CLUSTER_ID` to be consistent with `SocaConfig` naming convention
- ERROR/WARNING and FATAL bootstrap log messages are now copied to discrete log files in addition to standard stdout log
- Reworked Linux System Packages template to simplify support for current and future operating systems
- Simplified `default_config.yml` syntax by removing un-necessary keys
- Adding `orchestrator` and `analytics` folder to the S3 logs backup mechanism
- Boto3 / botocore updated to `1.36.2`
- Python updated from `3.9.19` to `3.9.21`
- OpenMPI updated from `5.0.5` to `5.0.6`
- AWS EFA installer updated from `1.34.0` to `1.38.0`
- Added `m7i.large` and `m6i.large` as default instance types for consideration during installations
- Default to `TLS1.2` policy for OpenSearch deployments for better security and compatibility
- Default to `OpenSearch 2.17` engine for new installations where SOCA creates the OpenSearch cluster
- Update `OpenPBS` installation method to install from a specific GitHub `commitid` versus a specific release
  - This allows several defect fixes/updates since the most recent release of `OpenPBS`
  - This can be adjusted in the `default_config.yaml` to restore the previous behavior (**NOTE:** May contain defects that are already fixed!)
- Removed redundant/retired Lambdas (`ResetDSPassword`, `GetESPrivateIPLambda`) and associated resources as the functionality has been updated/replaced

### Fixes

- Improve the experience during installation to regions with limited instance type options.
- Various smaller fixes (typos, linting, etc)
- CloudFormation outputs now returns the correct VPC Endpoint for OpenSearch

### Known Issues

- Some BaseOS combinations may not work in all situations (Controller BaseOS, Compute Node, VDI, etc.) or features due to the age of the BaseOS. BaseOSes that are past their End of Life (EOL) support dates from the supplier may be removed in a future SOCA version.
- If you select differing architectures (e.g. `x86_64` and `arm64` for the instance_types in the cluster - the cluster will fail). This will be addressed in a future release.
- Linux VDI/DCV instances default to `Amazon Linux 2` - not the installed BaseOS of the cluster.
- Creating a VDI session with an unsupported name will filter-out the unsupported characters - potentially causing conflict with the CloudFormation stackname.
- Under rapid changes - the WebUI file browser may show incorrect results
- The default deployment makes use of synthetic POSIX `uid` and `gid` generated for linux instances via `sssd`. This is not compatible in all scenarios.
- Current Windows VDI images default to `40GB` root disks, and have approx `15GB` free after startup. This may not be enough for some larger installation packages. A larger default is expected in a future SOCA release.
- Windows VDI/DCV launches will fail in CloudFormation when using `ED25519` Key Pairs. This is not a SOCA restriction/defect. A future SOCA version will detect this and not allow the attempted launch.

## [24.10.0] - 2024-10-24

### Forward

Hello and welcome to the `24.10.0` release of SOCA! Please note the new version format is based on `CalVer` style versions.

Due to the amount of changes that have taken place we want to provide a bit more narrative on some of these changes versus a classic ChangeLog.

This release contains numerous improvements and fixes. We anticipate it being applicable to many more situations and being our best release yet!

Some areas of improvement with this release include:

- Improved Security
  - More specific IAM policy for restricted environments
  - SSH keys are now generated for `RSA` and `ED25519` key types automatically for new users (Support for `DSA` and `ECDSA` is being removed in general industry-wide in early 2025)

  - Discrete Security Groups providing fine-grained access control adjustments for more resources
    - Elastic Load Balancers, Compute Nodes, Controller Host, Login Nodes, VPC-Endpoints all now get discrete Security Groups.

  - Improved AWS Key Management Service (KMS) integration for specifying Customer Managed Keys (CMK)
    - Each resource now supports discrete KMS KeyIDs or a cluster-wide KeyID can be specified for ease of deployment

  - Improved behavior during installation into AWS Accounts with Service control policies (SCPs) or CDK restrictions
    - New options are exposed in the `soca_installer.sh` to pass CDK Execution roles which can be provisioned ahead of time

- Rewrite of several key areas for better debugging and readability
  - Improvements to installation logging/debugging as well as cluster runtime debugging

- Migration of the bulk of SOCA configuration settings from `AWS Secrets Manager` to `AWS System Manager Parameter Store`.
  - This now makes editing individual configuration settings more intuitive.
  - Don't worry - Secrets Manager is still used for sensitive configuration items!

- Version upgrades to keep up with current external package advancements

- Deprecation of self-hosted OpenLDAP in favor of using `AWS Directory Service` or `External Directories`.
  - This is an important step to refreshing and streamlining our BaseOS support in future versions as it decouples the BaseOS from the availability of an OpenLDAP-server package
  - Expect this to provide newer BaseOS support in the future

- Improved logic for handling newer instance types as soon as they are available (`zero-day instance support`)
  - This is critical for supporting newer instances without the need to upgrade any SOCA cluster components

- Reduction of running costs of the SOCA cluster
  - Support for `Amazon ElastiCache Serverless` (replaces `Redis` running on the `controller` directly)
  - Ability to disable `analytics` engine to remove the need for OpenSearch

- Improved use of `existing_resources` - Better resource polling during installation time to help identify the resources for use in SOCA.
  - The following resources can be used as `existing_resources` during a SOCA installation:
    - VPCs, Subnets, Filesystems (EFS, FSx), Security Groups, Directory Services, IAM Roles

As always we value your feedback - please do not hesitate to leave a GitHub issue/discussion if you are having any specific problems or want to discuss the future of SOCA.

Thank you,

- The SOCA Team

And now - back to your normal ChangeLog :)

### Features

- Updated SOCA versioning to [CalVer](https://calver.org/) format.
- SOCA now automatically create a default admin user `socaadmin` with a secure password stored in AWS Secrets Manager
- Added support for `SSH Login Nodes`. Login Nodes are SSH endpoints managed by AutoScaling running on Private Subnets and accessible via a newly introduced Network Load Balancer. Network Load Balancer can be deployed either in public or private subnets.
- Added `socactl` CLI utility as an interface for SOCA configuration. You can now update your entire SOCA environment with a simple command.
- Migrated SOCA Configuration to AWS System Manager Parameter Store
- Remove support for `ElasticSearch`. `Amazon OpenSearch` is now the only option for the analytics back-end.
- Migrated `cluster_node_boostrap` shell/powershell scripts to full Jinja2 support
- Enable debug log for web interface, orchestrator ... via `export SOCA_DEBUG=1`
- Added support for `ldaps://` (default) in addition of `ldap://` when using OpenLDAP
- Added support for `AWS Directory Service Simple Active Directory` in addition of `AWS Directory Service Managed AD`
- Added native support for existing `OpenLDAP` or existing `Active Directory` directory service
- OpenPBS / Workload scheduler can now be installed from `git` or `s3 URI`
- OpenSearch / Analytics is now optional
- Initial support added for `AWS Backup logically air-gapped vaults` via the `additional_copy_destinations` in the `default_config.yml` configuration file. This allows for increased protection of critical backups. See [this blog post](https://aws.amazon.com/blogs/storage/building-cyber-resiliency-with-aws-backup-logically-air-gapped-vault/) for information on `Logically Air-gapped Vaults`. Additional configuration information can be found in the `default_config.yml` `backup` configuration section.
- Added new `utils` class to help you customize your SOCA environment:
  - `SocaCacheClient`: Cache wrapper (currently only support Redis/ValKey on Amazon ElastiCache)
  - `SocaCastEngine`: Easily cast variables to requested type
  - `SocaConfig`: Wrapper for SOCA Configuration on Parameter Store
  - `SocaError`: Database for all errors returned by SOCA
  - `SocaIdentityProviderClient`: Wrapper for OpenLDAP or Active Directory
  - `SocaHttpClient`: HTTP client for all SOCA internal endpoints
  - `SocaLogger`: Centralized Logging framework
  - `SocaSubprocessClient`: Wrapper to execute shell commands on SOCA
  - `SocaReponse`: Wrapper for CLI/HTTP response that can be invoked in a CLI or web context
  - `SocaJinja2Generator`: Wrapper for Jinja2 template generation
  - `SocaAnalyticsClient`: Wrapper for OpenSearch

### Changed

- `Scheduler` has been replaced with `Controller` to better indicate the role in the SOCA environment. Some areas may still refer to this as `Scheduler` as this gets updated over time.
- `Login Node` has been introduced to provide CLI access for end-users (they are no longer expected to log in to the scheduler/controller directly)
- `Controller` host has been automatically moved to Private Subnets
- `Controller` host instance type has been updated to `m7i-flex.large` from `m5.large`
- Configurations in `default_config.yml` that takes `instance_type` now take a list of instances. These will be determined at deployment time based on the order of preference (first match wins).
- Make use of `Amazon ElastiCache Serverless` instead of downloading/compiling Redis directly on the Scheduler/Controller
- Updated OpenSearch default version to `2.15`
- Updated Node.js on Controller Host to v`20.9.0` where applicable (some older BaseOSes may run older/compatible versions)
- Updated AWS EFA installer from `1.31.0` to `1.34.0`
- Updated OpenMPI from `5.0.2` to `5.0.5`
- Updated `monaco-editor` from `0.46.0` to `0.52.0`
- Consolidated `cluster_manager` file folder hierarchy
- Moved the SOCA AMI Map (aka the `Region Map`) to a dedicated file `region_map.yml` from the `default_config.yml`. Custom Base AMIs can be updated here.
- The SOCA CLI installer will now check/enforce that an existing VPC has the attributes`DNS hostnames` and `DNS resolution` enabled. Non-compliant VPCs will show an error indicating the missing attribute and will not be selectable.
- When adding a new user - SSH keys are now generated for `RSA` and `ED25519` key types. Note the deprecation of `DSA` and `ECDSA` has been taking place for nearly a decade and will soon be unavailable in OpenSSH.
- The configuration element `DCVAllowedInstances` did not default to the entries from `default_config.yml`. This has been fixed.

### Known Issues

- Some BaseOS combinations may not work in all situations (Controller BaseOS, Compute Node, VDI, etc.) or features due to the age of the BaseOS. BaseOSes that are past their End of Life (EOL) support dates from the supplier may be removed in a future SOCA version.
- If you select differing architectures (e.g. `x86_64` and `arm64` for the instance_types in the cluster - the cluster will fail). This will be addressed in a future release.
- Linux VDI/DCV instances default to `Amazon Linux 2` - not the installed BaseOS of the cluster.
- Creating a VDI session with an unsupported name will filter-out the unsupported characters - potentially causing conflict with the CloudFormation stackname.
- Under rapid changes - the WebUI file browser may show incorrect results
- The default deployment makes use of synthetic POSIX `uid` and `gid` generated for linux instances via `sssd`. This is not compatible in all scenarios.
- Current Windows VDI images default to `40GB` root disks, and have approx `15GB` free after startup. This may not be enough for some larger installation packages. A larger default is expected in a future SOCA release.
- Windows VDI/DCV launches will fail in CloudFormation when using `ED25519` Key Pairs. This is not a SOCA restriction/defect. A future SOCA version will detect this and not allow the attempted launch.

## [2.7.5] - 2024-04-10

### Features

- Support for [Amazon Linux 2023](https://aws.amazon.com/linux/amazon-linux-2023/) as a BaseOS for compute nodes
  - eVDI on Amazon Linux 2023 is not currently supported
- Support for `5 new AWS Regions`: `ap-northeast-3`, `ap-southeast-4`, `eu-central-2`, `eu-south-2`, and `il-central-1`.
  - Note that not all Base OSes are available in All regions
- Support for `RHEL8`, `RHEL9`, `Rocky8`, and `Rocky9` operating systems for both DCV and compute nodes
- Support for newer AWS Instance types/families. This includes `hpc7a`, `hpc7g`, `r7iz`, `g6`, `gr6`, `g5`, `g5g`, `c7i`, `p5`, and many more (where supported in the region)
- Support for [AWS GovCloud](https://aws.amazon.com/govcloud-us/) Partition installation by default
  - Include AMIs for regions `us-gov-west-1` and `us-gov-east-1`
  - Note that not all Base OSes are available in All regions within GovCloud
  - Set environment variable `AWS_DEFAULT_REGION` to a GovCloud region prior to invoking `soca_installer.sh`
- Improve compatibility and support SOCA deployments on `AWS Outposts` (compute, eVDI)
  - The default `VolumeType` in Secrets Manager needs to be configured to reflect the AWS Outposts `gp2` support
- Support has been added for multi-interface EFA instances such as the `p5.48xlarge`. For compute instances that support multiple EFA interfaces - all EFA interfaces will be created during provisioning.
- The SOCA Administrator can now define the list of approved eVDI instances via new configuration parameters:
  - `DCVAllowedInstances` - A list of patterns for allowed instance names. For example `["m7i-flex.*", "m7i.*", "m6i.*", "m5.*", "g6.*", "gr6.*", "g5.*", "g5g.*", "g4dn.*", "g4ad.*"]`
  - (Optional) `DCVAllowBareMetal` (defaults to `False`) - Allow listing of Bare Metal instances for eVDI
  - (Optional) `DCVAllowPreviousGenerations` (defaults to `False`) - Allow listing of previous generation(s) of instances for eVDI

### Changed

- Improved user experience using `soca_installer.sh` in high-density VPC/subnet environments
- Improved the log message for an Invalid `subnet_id` during job submission to include the specific `subnet_id` that triggered the error
- Updated Python from `3.9.16` to `3.9.18`
- Updated AWS Boto3/botocore from `1.26.91` to `1.34.71`
- Updated OpenMPI from `4.1.5` to `5.0.2`
- Updated OpenPBS from `22.05.11` to `23.06.06`
- Updated Monaco-Editor from `0.36.1` to `0.46.0`
- Updated AWS EFA installer from `1.22.1` to `1.31.0`
- Updated NICE DCV from `2023.0-14852` to `2023.1-16388` (except for RHEL7 and CentOS7)
- Update NVM from `0.39.3` to `0.39.7`
- Updated Node from `16.15.0` to `16.20.2`
- Updated Lambda Runtimes to Python `3.11` where applicable
- Misc Python 3rd party module version updates
- Refactor installation items for newer AWS CDK methods
- Updated default `OpenSearch` engine version to `2.11` when creating an OpenSearch deployment
- The use of `add_nodes.py` to add `AlwaysOn` nodes now allows the parameter `--instance_ami` to be optional and will default to the `CustomAMI` in the cluster configuration
- Download/install/configure `Redis` version `7.2.4` for new SOCA cache backend
- The SOCA ELB/ALB is now created with the option `drop_invalid_headers` set to `True` by default.
- Several UWSGI application server adjustments
  - Activate UWSGI `stats` server on `127.0.0.1:9191`
  - Activate UWSGI `offload-threads`
  - Activate UWSGI `threaded-logger`
  - Activate UWSGI `memory-report`
  - Activate UWSGI `microsecond logging`
  - Activate UWSGI logging of the `X-Forwarded-For` headers so that the client IP address is captured versus the ELB IP Address
  - Added `uwsgitop` to assist in UWSGI performance investigations. This can be accessed via the command `uwsgitop localhost:9191` from the scheduler.
  - Adjusted Flask session backend from `SQLite` to `redis`. This results in a much faster WebUI/session handling.
  - **NOTE** - Upgrade scenarios should take UWSGI changes into account and manually perform Redis installation/configuration and session migration.
- `Launch Tenancy` and `Launch Host` have been added as options when registering an AMI in SOCA. These will be used during DCV session creation.
  - For more information on launch tenancy - see the [documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/dedicated-instance.html).
- Updated default OpenSearch instance from `m5.large.search` to `m6g.large.search`
- Updated default VDI choices from `m5` to `m6i` instance family
- `instance_ami` is no longer mandatory when specifying a custom `base_os`. SOCA will determine which default AMI to use automatically via the `CustomAMIMap` configuration stored on Secrets Manager.
- Changed default `instance_type` for all base HPC queues from `c5` to `c6i` instance family
- Updated DCV Session default `Storage Size` to `40GB` to accommodate additional locally installed software such as GPU drivers, libs, etc.

### Fixes

- `DryRun` job submission was not taking into account the `IMDS` settings for the cluster. This could cause job submission to fail `DryRun` and not be submitted.
- Installation using an existing `OpenSearch` / `ElasticSearch` domain was not working as expected. This has been fixed.
- Avoid sending `CpuOptions` with `hpc7a`, `hpc7g`, `g5`, `g5g` instances. This will fix launching on these instance families.
- Properly detect newer AWS metal instances for determining if `CpuOptions` is supported during instance launch. This will allow launching `c7i.metal-24xl`, `c7i.metal-48xl` (and others) to function properly
- On the `scheduler` Post-Install - extract/compile `OpenMPI` on a local EBS volume instead of EFS (can reduce compile time by `50%+`)
- During HPC Job submission within the WebUI - the multi-select UI element `Checkbox Group` was not passed correctly to the underlying job scripting
  - `Checkbox Group` element values will be delimited by comma by default (e.g. `option1,option2`).
  - Care should be taken to not have option values contain the delimiter character. This can be updated in `submit_job.py` as needed. (Option name fields can contain the delimiter character)
- During DCV Session creation - the user was allowed to enter a session name that exceeded the allowable length for a CloudFormation stack name. This has been adjusted to trim the session name to appropriate length (32 characters).
- During DCV Session creation - if the session contained an underscore (\_) the session would produce an error and not be created.
- During DCV Session creation - The `Storage Size` was allowed to be lower than a stored AMI. This will now default / auto-size to the AMI specification.
- Bootstrap tooltips are now displayed using the correct CSS in the Remote Desktop pages
- Previously during invocation of `soca_installer.sh` with existing resources - only VPCs and Subnets with AWS `Name` tags would be selectable. This restriction has been eased to allow resources without `Name` tags to be selectable.
- Under certain conditions in an Active Directory (AD) environment - the `scheduler` computer object could be mistakenly replaced in AD by an incoming compute or VDI node. This was due to NetBIOS name length restrictions causing name conflicts. This has been corrected.

### Known Caveats

- Web Sessions can be stored in the back-end (redis) that relate to API calls or other situations where return of the session is not expected. These sessions will be cleaned up automatically by Redis when the TTL expires (24hours).
- On the Remote Desktop selection for Instance Types - sorting, grouping, and custom names of the AWS instances is not configurable by the SOCA Administrator for wildcard instances allowed via wildcard (e.g. `g5.*`).
  - This can cause 'selection fatigue' for end-users when a large number of instances types are allowed.
  - The SOCA Administrator can configure the static list at the top before the generated list appears. See the `cluster_web_ui/templates/remote_desktop.html` (Linux) and `cluster_web_ui/templates/remote_desktop_windows.html` (Windows) files for examples/defaults.
  - The SOCA Administrator can reduce the default instances allowed by editing the AWS Secrets Manager configuration entry for the cluster and refreshing the configuration on the cluster.

## [2.7.4] - 2023-05-08

### Features

- Support for newer AWS EC2 instances since the last release.
  - HPC family (in supported regions): `hpc6a.48xlarge`, `hpc6id.32xlarge`
- Updated Region support list with new regions for SOCA deployment
- Updated all AMIs to point to newer versions
- Added support for OpenSearch.
  - OpenSearch will be the default option in the future release and will replace ElasticSearch
  - MetricBeat will be sunset once OpenSearch replace ElasticSearch
- The SOCA head node can now be installed onto an AWS Graviton processors(`arm64`) in regions where available. The `scheduler/instance_type` will have the architecture determined at installation time for selecting the correct AMI.
- IMDSv2 metadata is now enforced for all EC2 hosts. This setting change be changed on the config file. (contributor: @sebastiangrimberg [#84](https://github.com/awslabs/scale-out-computing-on-aws/pull/84)

### Changed

- boto3 updated from `1.17.49` to `1.26.61`
- botocore updated from `1.20.49` to `1.29.61`
- troposphere requirements are now `>= 4.3.0`. Updated from `2.7.1` to `4.3.2`
- Python updated from `3.7.9` to `3.9.19`
- OpenPBS updated from `20.0.1` to `22.05.11`
- AWS EFA installer updated from `1.13.0` to `1.22.1`
- OpenMPI updated from `4.1.1` to `4.1.5`
- NICE DCV framework updated from `2021.2` to `2023.0-14852`
- NVM updated from `0.38.0` to `0.39.3`
- Update Monaco-editor from ``to`0.36.1`
- EPEL RPM updated to `-9`
- Updates to several downstream python requirements/modules
- Added support for `Version`, `Region`, `Misc` in anonymous metrics
- Changed default OpenPBS Job History Duration (`job_history_duration`) to `72-hours` (from `1-hour`)
- Improved Python/OpenPBS compilation to make consistent use of `nproc` CPUs/jobs (`make -j N`)
- Upgraded Amazon Cloud Development Kit (CDK) to `v2`
- Added `skip_quota` flag to disable quota checks when using subnets with no egress
- The default queues that are created will now default to using the instance type of the scheduler instance. This is to align CPU architectures and the selected BaseOS AMI.
- Upgraded Jquery to `3.6.4`
- Upgraded Bootstrap to `4.6.3`
- Updated lustre client installation for Amazon Linux 2 enabling installation of lustre2.12 client required for FSx File Cache

### Fixes

- Fixed instances matching the incorrect Service Quota and preventing job execution under some circumstances (contributor: @nfahlgren [#81](https://github.com/awslabs/scale-out-computing-on-aws/pull/81)).
- Fixed anonymous metric submission during job delete.
- Fixed detection of IP address during `soca_installer.sh` by using https://checkip.amazonaws.com
- Fix attempt to set `CpuOptions` on instance types that do not support `CpuOptions`
- Additional exception handling during installation when the ALB is not ready yet and emits a connection refused.
- Added PBS_LEAF_NAME in ComputeNode.sh pbs.conf section to address pbs_mom to pbs_comm communication when there are multiple network interfaces in the AMI
- Added REQUIRE_REBOOT logic in ComputeNode.sh to skip instance reboot if not needed (mostly when using a customized AMI)

## [2.7.3] - 2022-08-20

### Changed

- Bumped Lambda Python Runtime to 3.7

## [2.7.2] - 2022-04-25

### Changed

- Fix node version to v8.7.0 (later versions need updated versions of GLIBC that are not available for AL2/CentOS7/RHEL7)
- Update RHEL7 AMI IDs to RHEL7.9
- Update AL2 AMI IDs

## [2.7.1] - 2022-02-15

### Changed

- Node.js/npm is now managed via NVM (#64: Contributor @cfsnate)
- Fixed IAM policies required to install SOCA and added support for cdk boostrap (#64: Contributor @cfsnate)
- More consistent way to install EPEL repository across distros
- Better way to install SSM on the Scheduler host (similar to what we are already doing with ComputeNodes)
- Updated remote job submission to fix error with group ownership when using a remote input file
- DCV desktops now honor correct subnet when specified
- Fix issue causing installer to crash when using IPv6-only VPC subnets
- Fix logger issue on DCV instance lifecycle (#67, contributor @tammy-ruby-cherry)

## [2.7.0] - 2021-11-18

### Added

- SOCA installer is managed by CDK (https://aws.amazon.com/cdk/)
- Enabled full WSGI debug mode for SOCA Web UI
- Added support for WeightedCapacity enabling add_nodes.py to launch capacity based on vCPUs or cores
- CDK: Added support for Active Directory via AWS Directory Service
- CDK: Users can now re-use their existing AWS resources (VPC, subnets, security groups, FSxL, EFS, Directory Services ...) when installing SOCA
- CDK: Users can extend the base installer with their own code (see cdk_construct_user_customization)
- CDK: /apps & /data partition can now be configured to use EFS or FSxL as storage provider
- CDK: Users can now use your own CMK (Customer Managed Key) to encrypt your EFS, FSxL, EBS or SecretsManager
- CDK: Users can configure the number of NAT gateways to be deployed when installing a new cluster
- CDK: Users can customize your OpenSearch (formerly Elasticsearch) domain (number of nodes, type of instance)
- CDK: Users can configure the backup retention time (default to 7 days)
- CDK: Users can now deploy SOCA in private subnets only
- CDK: Added support for VPC endpoints creation
- Users can now specify up to 4 additional security groups for compute nodes assigned to their simulations
- Users can now specific a custom IAM instance profile for compute nodes assigned to their simulations
- Deprecated ldap_manager.py in favor of the native REST API
- Added a custom path for Windows DCV logs
- Name of the SOCA cluster is now accessible on the Web interface
- DCV session management is now available via REST API
- Customer EC2 AMI management is now available via REST API
- Added job-shared queue enabling multiple jobs to run on the same EC2 instance for jobs with similar requirements
- Desktops sessions are now tracked on OpenSearch (formerly Elasticsearch) via "soca_desktops" index

### Changed

- Upgraded DCV to 2021.2
- Upgraded EFA to 1.13.0
- Upgraded OpenMPI to 4.1.1
- Auto-Terminate stopped DCV instances now delete the associated cloudformation stack
- Fixed #55 (bug and bug fix: automatic hibernation (Linux desktops))
- Prevent system accounts (ec2-user/centos) to submit jobs
- OpenMPI is now installed under /apps/openmpi
- Changed default OpenSearch (formerly Elasticsearch) indexes to "soca_jobs" and "soca_nodes" (previously "jobs" and "pbsnodes")

## [2.6.1] - 2021-03-22

### Added

- Added Name tag to EIPNat in Network.template
- Added support for Milan and Cape Town
- EBS volumes provisioned for DCV sessions (Windows/Linux) are now tagged properly
- Support for Graviton2 instances
- Ability to disable web APIs via @disabled decorator

### Changed

- Updated EFA to 1.11.1
- Updated Python 3.7.1 to Python 3.7.9
- Update DCV version to 2020.2
- Updated awscli, boto3, and botocore to support instances announced at Re:Invent 2020
- Use new gp3 volumes instead of gp2 since they're more cost-effective and provide 3000 IOPS baseline
- Removed SchedulerPublicIPAllocation from Scheduler.template as it's no longer used
- Updated CentOS, ALI2 and RHEL76 AMI IDs
- Instances with NVME instance store don't become unresponsive post-restart due to filesystem checks enforcement
- OpenSearch (formerly Elasticsearch) is now deployed in private subnets

## [2.6.0] - 2020-10-29

### Added

- Users can now launch Windows instances with DCV
- Users can now configure their DCV sessions based on their own schedule
- Users can stop/hibernate DCV sessions
- Users can change the hardware of their DCV sessions after the initial launch
- Admins can create DCV AMI with pre-configured applications
- Added support for DCV session storage. Upload/download data to SOCA directly from your DCV desktop (C:\storage-root for windows and $HOME/storage-root for linux)
- Admins can now prevent users to download the files via the web ui
- SOCA automatically enable/disable EFS provisioned throughput based on current I/O activity

### Changed

- Removed deprecated `soca_aws_infos` hook
- Fixed an issue that caused the web interface to become unresponsive after an API reset
- Users can now easily import/export application profiles
- Fixed an issue that caused NVIDIA Tesla drivers to be incorrectly installed on P3 instances
- Manual_build.py now automatically upload the installer to your S3 bucket
- Upgraded to PBS v20
- Upgraded DCV to 2020.1-9012

## [2.5.0] - 2020-07-17

### Added

- Support for Elastic MetricBeat
- Added HTTP REST API to interact with SOCA
- Users can now decide to restrict a job to Reserved Instances
- Revamped Web Interface
  - Added filesystem explorer
  - Users can upload files/folders via drag & drop interface
  - Users can edit files directly on SOCA using a cloud text editor
  - Users can now manage membership of their own LDAP group via web
  - Users can now understand why they job is not started (eg: instance issue, misconfiguration, AWS limit, license limit) directly on the UI
  - Users can kill their job via the web
  - Admins can manage SOCA LDAP via web (create group, user, manage ownership and permissions)
  - Admins can create application profiles and let user submit job via web interface
  - Ability to trigger Linux commands via HTML form
- Admins can now limit the number of running jobs per queue
- Admins can now limit the number of running instances per queue
- Admins can now specify the idle timeout value for any DCV sessions. Inactive DCV sessions will be automatically terminated after this period
- Job selection can now be configured at queue level (FIFO or fair share)
- Dry run now supports vCpus limit
- Support for custom shells

### Changed

- Updated Troposphere to 2.6.1
- Updated EFA to 1.9.3
- Updated Nice DCV to 2020.0-8428
- Updated OpenSearch (formerly Elasticsearch) to 7.4
- You can specify a name for your DCV sessions
- You can now specify custom AMI, base OS or storage options for your DCV sessions
- Project assigned to DCV jobs has been renamed to "remotedesktop" (previously "gui")
- Dispatcher script is now running every minute
- SOCA now deploys 2 instances for OpenSearch (formerly Elasticsearch) for high availability
- Users can now specify DEPLOYMENT_TYPE for their FSX for Lustre filesystems
- Users can specify PerUnitThroughput when FSx for Lustre deployment type is set to PERSISTENT
- DCV now supports G4 instance type (#24)
- X11 is now configured correctly for ALI 3D DCV session (#23)

## [2.0.1] - 2020-04-20

### Added

- Support for SpotFleet

### Changed

- NVIDIA drivers are now automatically installed when a GPU instance is provisioned
- Deployed MATE Desktop for DCV for Amazon Linux 2

## [2.0.0] - 2020-03-18

### Added

- Support for MixedInstancePolicy and InstanceDistribution
- Support for non-EBS optimized instances such as t2
- Integration of AWS Session Manager
- Integration of AWS Backup
- Integration of AWS Cognito
- Integration of Troposphere
- Admins can now manage ACL (individual/LDAP groups) at queue level
- Admins can now restrict specific type/family of instance at queue level
- Admins can now prevent users to change specific EC2 parameters
- Users can now install SOCA using existing resources such as VPC, Security Groups ...
- Users now have the ability to retain EBS disks associated to a simulation for debugging purposes
- SOCA now prevent jobs to be submitted if .yaml configuration files are malformed
- Scheduler Root EBS is now tagged with cluster ID
- Scheduler Network Interface is now tagged with cluster ID
- Scheduler and Compute hosts are now sync with Chrony (Amazon Time Sync)
- Support for FSx for Lustre new Scratch2/Scratch1 and Persistent mode
- Added Compute nodes logs on EFS (/opt/soca/<cluster_id>/cluster_node_bootstrap/logs/<job_id>/<host>/\*.log) for easy debugging

### Changed

- Ignore installation if PBSPro is already configured on the AMI
- Fixed bug when stack name only use uppercase
- ComputeNode bootstrap scripts are now loaded from EFS
- Users can now open an SSH session using SSM Session Manager
- Processes are now automatically launched upon scheduler reboot
- Max Spot price now default to the OD price
- Default admin password now supports special characters
- Ulimit is now disabled by default on all compute nodes
- Dispatcher automatically append "s3://" if not present when using FSx For Lustre
- Updated default OpenSearch (formerly Elasticsearch) instance to m5.large to support encryption at rest
- SOCA libraries are now installed under /opt/soca/<CLUSTER_ID> location to support multi SOCA environments
- Web UI now display the reason when a DCV job can't be submitted
- Customers can now provision large number of EC2 hosts across multiple subnets using a single API call
- Smart detection of Placement Group requirement when using more than 1 subnet
- Added retry mechanism for some AWS API calls which throttled when provisioning > 1000 nodes in a single API call
- ALB Target Groups are now correctly deleted once the DCV sessions is terminated
- SOCA version is now displayed on the web interface
- Updated EFA version to 1.8.3

## [1.0.0] - 2019-11-20

- Release Candidate
