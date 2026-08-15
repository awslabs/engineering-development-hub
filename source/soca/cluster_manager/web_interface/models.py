# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import ENUM
from extensions import db
import datetime
from sqlalchemy import event
from flask import has_request_context, session, request
from sqlalchemy.sql import func, text
from sqlalchemy.sql import exists, and_, or_, not_
from typing import List, Set, Type
from sqlalchemy.orm import Session

SessionState = ENUM("pending", "placing", "running", "stopping", "stopped", "error", "interrupting", "interrupted", name="session_state_enum")
OSFamily = ENUM("linux", "windows", name="os_family")
MembershipState = ENUM("allow", "deny", name="membership_state")
IdentityName = ENUM("user", "group", name="identityName")


# Association table to link projects and software stacks
project_software_stack_association = Table(
    "project_software_stack",
    db.Model.metadata,
    db.Column(
        "project_id",
        db.Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "software_stack_id",
        db.Integer,
        ForeignKey("software_stacks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

project_target_node_software_stack_association = Table(
    "project_target_node_software_stack",
    db.Model.metadata,
    db.Column(
        "project_id",
        db.Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "software_stack_id",
        db.Integer,
        ForeignKey("target_node_software_stacks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

user_data_target_node_software_stack_association = Table(
    "target_node_user_data_software_stack",
    db.Model.metadata,
    db.Column(
        "template_id",
        db.Integer,
        ForeignKey("target_node_user_data.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "target_node_software_stack_id",
        db.Integer,
        ForeignKey("target_node_software_stacks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

project_application_profile_association = Table(
    "project_application_profile",
    db.Model.metadata,
    db.Column(
        "project_id",
        db.Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "application_profile_id",
        db.Integer,
        ForeignKey("application_profiles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class BaseModel(db.Model):
    __abstract__ = True
    updated_by = db.Column(db.String(255))
    updated_on = db.Column(db.DateTime, default=func.now(), onupdate=func.now())

    def __repr__(self):
        pk_names = [key.name for key in self.__mapper__.primary_key]
        pk_values = ", ".join(f"{name}={getattr(self, name)}" for name in pk_names)
        return f"<{self.__class__.__name__} {pk_values}>"

    def as_dict(self, exclude_columns=None):
        exclude_columns = set(exclude_columns or [])
        return {
            c.name: getattr(self, c.name)
            for c in self.__table__.columns
            if c.name not in exclude_columns
        }


@event.listens_for(BaseModel, "before_update", propagate=True)
def receive_before_update(mapper, connection, target):
    if has_request_context():
        if "user" in session:
            target.updated_by = session["user"]
        elif request.headers.get("X-EDH-USER"):
            target.updated_by = request.headers.get("X-EDH-USER")
        else:
            target.updated_by = "UNKNOWN"
    else:
        target.updated_by = "UNKNOWN"



class ApiKeys(BaseModel):
    __tablename__ = "api_keys"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    scope = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    deactivated_on = db.Column(db.DateTime)


class ApiTokens(BaseModel):
    __tablename__ = "api_tokens"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    token_type = db.Column(db.String(20), nullable=False, default="user")
    token_hint = db.Column(db.String(14), nullable=False)
    token_hash = db.Column(db.String(128), nullable=False, unique=True)
    permissions = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    renewable = db.Column(db.Boolean, nullable=False, default=True)
    max_renewals = db.Column(db.Integer, nullable=True)
    renewal_count = db.Column(db.Integer, nullable=False, default=0)
    last_used_at = db.Column(db.DateTime, nullable=True)
    last_used_ip = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.String(255), nullable=False)

    __table_args__ = (
        db.Index("idx_api_tokens_user", "user", "token_type", "revoked_at"),
        db.Index("idx_api_tokens_hash", "token_hash"),
    )

    @property
    def is_expired(self):
        from datetime import datetime, timezone
        exp = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=timezone.utc)
        return exp < datetime.now(timezone.utc)

    @property
    def is_active(self):
        return not self.revoked_at and not self.is_expired


class ApiAuditLog(BaseModel):
    __tablename__ = "api_audit_log"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    user = db.Column(db.String(255), nullable=False)
    token_id = db.Column(db.Integer, nullable=True)
    token_name = db.Column(db.String(100), nullable=True)
    token_type = db.Column(db.String(20), nullable=True)
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(512), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(512), nullable=True)
    request_id = db.Column(db.String(64), nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)
    denied_reason = db.Column(db.String(50), nullable=True)
    actor_type = db.Column(db.String(20), nullable=True)
    source_ref = db.Column(db.String(255), nullable=True)
    on_behalf_of = db.Column(db.String(255), nullable=True)
    via_ip = db.Column(db.String(45), nullable=True)

    __table_args__ = (
        db.Index("idx_audit_log_user_time", "user", "timestamp"),
        db.Index("idx_audit_log_token", "token_id", "timestamp"),
        db.Index("idx_audit_log_path", "path", "timestamp"),
        db.Index("idx_audit_log_time", "timestamp"),
        db.Index("idx_audit_log_actor_time", "actor_type", "timestamp"),
    )


class ApplicationProfiles(BaseModel):
    __tablename__ = "application_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_by = db.Column(db.String(255), nullable=False)
    profile_name = db.Column(db.String(255), nullable=False, unique=True)
    profile_form = db.Column(db.Text, nullable=False)
    profile_job = db.Column(db.Text, nullable=False)
    profile_interpreter = db.Column(db.Text, nullable=False)
    profile_thumbnail = db.Column(db.Text, nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    deactivated_on = db.Column(db.DateTime)

    # Relationships
    projects = relationship(
        "Projects",
        secondary=project_application_profile_association,
        back_populates="application_profiles",
    )

    def as_dict(self, exclude_columns=None):
        result = super().as_dict(exclude_columns=exclude_columns)
        if self.projects:
            result["projects"] = [p.id for p in self.projects]
        else:
            result["projects"] = []

        return result


class VirtualDesktopSessions(BaseModel):
    __tablename__ = "virtual_desktop_sessions"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    is_active = db.Column(db.Boolean, nullable=False)  # If session is active or not
    created_on = db.Column(
        db.DateTime, nullable=False
    )  # Timestamp when session was created
    deactivated_on = db.Column(db.DateTime)  # Timestamp when session was deleted
    deactivated_by = db.Column(db.String(255))
    stack_name = db.Column(
        db.String(255), nullable=False
    )  # Name of the CloudFormation Stack
    session_uuid = db.Column(
        db.String(36), nullable=False, index=True
    )  # Manage EC2 tag edh:DCVSessionUUID as well as session ID
    session_name = db.Column(
        db.String(255), nullable=False
    )  # Session name specified by the user
    session_project = db.Column(db.String(255), nullable=False)  # Project
    session_state = db.Column(SessionState, nullable=False)
    session_type = db.Column(db.String(255), nullable=False)  # console or virtual
    session_state_latest_change_time = db.Column(db.DateTime, nullable=False)
    session_local_admin_password = db.Column(
        db.String(255)
    )  # Local admin password for the session (Optional)
    session_token = db.Column(db.String(255))  # Unique token associated to each session
    schedule = db.Column(db.Text, nullable=False)  # DCV session schedule
    session_thumbnail = db.Column(db.Text)  # DCV session screenshot
    software_stack_id = Column(
        Integer, ForeignKey("software_stacks.id"), nullable=False
    )  # ID of the software Stack deployed on this machine

    # DCV Specific
    session_owner = db.Column(
        db.String(255), nullable=False, index=True
    )  # Session owner
    session_id = db.Column(
        db.Text, nullable=False
    )  # Same as session_uuid for Linux, default to console for windows. This is the ID of your DCV Session
    authentication_token = db.Column(
        db.Text
    )  # Encrypted authentication token, contains session_token and others info. Fernet-encrypted blob can exceed 255 chars

    # Instance Specific
    instance_private_dns = db.Column(db.String(255))  # Private DNS of the EC2 host
    instance_private_ip = db.Column(db.String(255))  # Private IP of the EC2 host
    instance_id = db.Column(db.String(255))  # Instance ID of the EC2 host
    instance_type = db.Column(
        db.String(255), nullable=False
    )  # Instance type of the EC2 host
    instance_base_os = db.Column(
        db.String(255), nullable=False
    )  # Base OS of the EC2 host
    os_family = db.Column(OSFamily, nullable=False)
    ssm_ping_status = db.Column(
        db.String(20), default="Unknown"
    )  # SSM Agent ping status: Online, ConnectionLost, Unknown
    support_hibernation = db.Column(
        db.Boolean, nullable=False
    )  # If EC2 host has hibernation turned on/off
    is_spot = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )  # EC2 Spot-backed desktop: ephemeral, not idle-stopped or resumed
    resume_saved_image_id = db.Column(
        db.Integer, index=True
    )  # If this session was launched by resuming a saved image, the vdi_saved_images.id;
    # the session_state_watcher consumes that image (single-use) once this session is running.

    # DCV high-scale event-relay (SQS+Lambda push) -- nullable, populated on
    # first VDI publish. See docs/DCVEventRelay.md for the full design.
    # Provenance is established via the AWS-attested SQS SenderId
    # (= role-id:i-XXXXXXXX) cross-checked against this row's instance_id;
    # no per-session secret is needed.
    last_seen_event_at = db.Column(
        db.DateTime
    )  # Wall-clock of the most recent accepted session-event from the VDI;
    # also updated by the cold-session probe on a successful describe.
    last_event_type = db.Column(
        db.String(64)
    )  # session-ready, session-resumed, session-failed, session-heartbeat, ...
    last_checkpoint = db.Column(
        db.String(64)
    )  # When last_event_type=bootstrap-checkpoint, this is the checkpoint
    # name (boot-started, dcv-installing, dcv-started, broker-registering,
    # broker-registered) so the grid timeline can SSR-paint the dot state
    # on page load without waiting for a live SSE event.
    session_ready_pushed_at = db.Column(
        db.DateTime
    )  # First session-ready event accepted (used as the "fast-path" promotion
    # signal -- watcher promotes pending->running on next tick when this is set).

    # Async placement: full launch context (JSON) parked here at create time.
    # The CapacityExecutor Lambda reads it back when ODCR placement succeeds.
    # Only IDs travel through SQS queues; passwords stay in the DB row.
    placement_context = db.Column(db.Text, nullable=True)

    # Relationships
    software_stack = relationship(
        "SoftwareStacks", back_populates="virtual_desktop_sessions"
    )


class DcvEventNonces(BaseModel):
    """
    Per-event nonce dedup for the DCV event-relay path.

    Every session-event published by a VDI carries a CSPRNG nonce in the
    body (32 bytes hex). The controller records (session_uuid, event_type,
    nonce) before applying the event; replays are rejected on the unique
    constraint. Rows expire after a fixed window (10 min default) since
    timestamps older than 5 min already fail the freshness check, so any
    nonce older than 10 min could not validate anyway.

    A small scheduled task (cleanup_dcv_event_nonces) prunes expired rows
    on each cycle so the table stays bounded even on long-lived clusters.
    """

    __tablename__ = "dcv_event_nonces"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_uuid = db.Column(db.String(36), nullable=False, index=True)
    event_type = db.Column(db.String(64), nullable=False)
    nonce = db.Column(db.String(128), nullable=False)
    accepted_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    __table_args__ = (
        db.UniqueConstraint(
            "session_uuid",
            "event_type",
            "nonce",
            name="uq_dcv_event_nonce_per_session_event",
        ),
    )


class DcvSessionEventLog(BaseModel):
    """
    Per-session event log for the DCV event-relay path.

    Every accepted session-event (lifecycle + substate) is appended here so
    the SSE stream endpoint can serve both live updates AND a recent-history
    timeline on the WebUI detail page. The table is the source of truth for
    "what did the bootstrap send and when" -- the VirtualDesktopSessions
    columns (last_seen_event_at, last_event_type, session_ready_pushed_at)
    capture only the latest signal, not the full timeline.

    Rows expire after 24h via the cleanup_dcv_event_log scheduled task
    (sibling of clean_tmp_folders). The table is intentionally append-only:
    no UPDATEs, only INSERTs and bulk DELETE-by-age. The SSE consumer
    reads with `ORDER BY event_timestamp ASC LIMIT N` (N typically 50).

    Indexes:
      - (session_uuid, event_timestamp): detail-page query path
      - received_at: cleanup task scan path

    Schema is intentionally narrow: checkpoint and sub_status mirror the
    body fields exactly so a future SSE payload formatter can serialize
    rows without enrichment.
    """

    __tablename__ = "dcv_session_event_log"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_uuid = db.Column(db.String(36), nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    checkpoint = db.Column(db.String(64), nullable=True)
    sub_status = db.Column(db.String(256), nullable=True)
    event_timestamp = db.Column(db.DateTime, nullable=False)
    received_at = db.Column(db.DateTime, nullable=False, index=True)

    __table_args__ = (
        db.Index(
            "ix_dcv_session_event_log_session_ts",
            "session_uuid",
            "event_timestamp",
        ),
    )


class SoftwareStacks(BaseModel):
    __tablename__ = "software_stacks"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stack_name = db.Column(db.Text, nullable=False)

    # AMI Information
    ami_id = db.Column(db.String(255), nullable=False)
    ami_arch = db.Column(db.String(255), nullable=False)
    ami_base_os = db.Column(db.String(255), nullable=False)
    ami_root_disk_size = db.Column(db.Integer, nullable=False)
    # Stack Info
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    deactivated_by = db.Column(db.String(255))
    deactivated_on = db.Column(db.DateTime)
    thumbnail = db.Column(db.Text, nullable=False)
    description = db.Column(
        db.String(500)
    )  # Admin can add useful information to the user, such as who own the software stack or support email
    virtual_desktop_profile_id = Column(
        Integer, ForeignKey("virtual_desktop_profiles.id"), nullable=False
    )
    # Allow for launch tenancy and host information to be saved with the AMI registration
    # https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-dedicated-instances.html
    # launch_host is nullable since it is not required (untargeted method)
    launch_tenancy = db.Column(db.String(255), nullable=False)
    launch_host = db.Column(db.String(255), nullable=True)
    os_family = db.Column(OSFamily, nullable=False)

    # DCV session sharing scope: 'none' | 'project' | 'cluster' (default).
    # Controls who a virtual desktop built from this stack may be shared with.
    # Nullable for backward-compat with rows created before this column existed;
    # readers treat NULL as 'cluster'.
    share_scope = db.Column(db.String(20), nullable=True, default="cluster")

    # Optional Hardware Profile binding. Nullable for backward-compat with rows
    # created before this column existed (same added-column pattern as
    # share_scope); readers treat NULL as "no hardware profile" (DCV defaults).
    # Project binding overrides this Stack binding when both are set.
    hardware_profile_id = db.Column(
        db.Integer,
        ForeignKey("hardware_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Per-stack EBS volume acceleration override (fast-restore). Nullable for
    # backward-compat (same added-column pattern as share_scope); NULL means
    # inherit the global /configuration/DCV/VolumeInitializationRate default.
    # Values: "off" (force lazy) | "100".."300" (PRVI MiB/s). "fsr" reserved.
    volume_acceleration = db.Column(db.String(20), nullable=True, default=None)

    # Relationships
    profile = relationship("VirtualDesktopProfiles", back_populates="software_stacks")
    hardware_profile = relationship(
        "HardwareProfiles", back_populates="software_stacks"
    )

    virtual_desktop_sessions = relationship(
        "VirtualDesktopSessions", back_populates="software_stack"
    )

    projects = relationship(
        "Projects",
        secondary=project_software_stack_association,
        back_populates="software_stacks",
    )

    def as_dict(self, exclude_columns=None, allowed_project_ids=None):
        exclude_columns = exclude_columns or []
        result = super().as_dict(exclude_columns=exclude_columns)

        if self.projects:
            filtered_projects = (
                [p for p in self.projects if p.id in allowed_project_ids]
                if allowed_project_ids
                else self.projects
            )

            result["projects"] = [
                {
                    column.name: getattr(p, column.name)
                    for column in p.__table__.columns
                    if column.name not in exclude_columns
                }
                for p in filtered_projects
            ]
            result["allowed_aws_budgets"] = list(
                dict.fromkeys(p.aws_budget for p in filtered_projects)
            )
            result["allowed_projects"] = list(
                dict.fromkeys(p.project_name for p in filtered_projects)
            )
        else:
            result["projects"] = []
            result["allowed_aws_budgets"] = []
            result["allowed_projects"] = []

        if self.profile:
            result["profile"] = {
                column.name: getattr(self.profile, column.name)
                for column in self.profile.__table__.columns
                if column.name not in exclude_columns
            }
        else:
            result["profile"] = {}

        return result


class VirtualDesktopProfiles(BaseModel):
    __tablename__ = "virtual_desktop_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    profile_name = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.Text)
    pattern_allowed_instance_types = db.Column(
        db.Text, nullable=False
    )  # csv of instance type,family allowed. Wildcard supported. Use Text -- explicit type lists can exceed 500 chars.
    allowed_instance_types = db.Column(
        db.Text, nullable=False
    )  # json of all instance types based on pattern, grouped by arch
    allowed_subnet_ids = db.Column(
        db.Text, nullable=False
    )  # csv of approved subnet ids. Wildcard supported. Use Text -- 20+ subnet IDs (~24 chars each) exceeds 500 chars.
    max_root_size = db.Column(db.Integer, nullable=False)  # max root size in GB

    software_stacks = relationship("SoftwareStacks", back_populates="profile")


class Projects(BaseModel):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    project_name = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.String(500))
    aws_budget = db.Column(db.String(255))

    # Optional Hardware Profile binding. Nullable added-column pattern; when
    # both a Project and its Software Stack bind a profile, Project wins.
    hardware_profile_id = db.Column(
        db.Integer,
        ForeignKey("hardware_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    hardware_profile = relationship(
        "HardwareProfiles", back_populates="projects"
    )
    software_stacks = relationship(
        "SoftwareStacks",
        secondary=project_software_stack_association,
        back_populates="projects",
    )

    target_node_software_stacks = relationship(
        "TargetNodeSoftwareStacks",
        secondary=project_target_node_software_stack_association,
        back_populates="projects",
    )

    application_profiles = relationship(
        "ApplicationProfiles",
        secondary=project_application_profile_association,
        back_populates="projects",
    )

    memberships = relationship("ProjectMemberships", back_populates="project")

    @property
    def allowed_users(self):
        return [
            m.identity_name
            for m in self.memberships
            if m.identity_type == "user" and m.state == "allow" and m.identity_name
        ]

    @property
    def denied_users(self):
        return [
            m.identity_name
            for m in self.memberships
            if m.identity_type == "user" and m.state == "deny" and m.identity_name
        ]

    @property
    def allowed_groups(self):
        return [
            m.identity_name
            for m in self.memberships
            if m.identity_type == "group" and m.state == "allow" and m.identity_name
        ]

    @property
    def denied_groups(self):
        return [
            m.identity_name
            for m in self.memberships
            if m.identity_type == "group" and m.state == "deny" and m.identity_name
        ]

    @classmethod
    def get_allowed_projects_for_user(
        cls, db_session: Session, user_name: str, groups: list
    ) -> Set[int]:
        """
        Returns set of allowed project IDs for a given user based on allow/deny rules
        matching their user identity or group memberships.
        """

        # DENY subquery: if there's *any* deny match for user_name, "*", or any group (checked by type)
        deny_subquery = (
            db_session.query(ProjectMemberships.project_id)
            .filter(
                ProjectMemberships.project_id == cls.id,
                or_(
                    # Deny matches for user
                    and_(
                        ProjectMemberships.identity_type == "user",
                        ProjectMemberships.identity_name.in_([user_name, "*"]),
                    ),
                    # Deny matches for groups
                    and_(
                        ProjectMemberships.identity_type == "group",
                        ProjectMemberships.identity_name.in_(groups),
                    ),
                ),
                ProjectMemberships.state == "deny",
            )
            .exists()
        )

        # ALLOW subquery: at least one allow match for user_name, "*", or any group
        allow_subquery = (
            db_session.query(ProjectMemberships.project_id)
            .filter(
                ProjectMemberships.project_id == cls.id,
                or_(
                    and_(
                        ProjectMemberships.identity_type == "user",
                        ProjectMemberships.identity_name.in_([user_name, "*"]),
                    ),
                    and_(
                        ProjectMemberships.identity_type == "group",
                        ProjectMemberships.identity_name.in_(groups),
                    ),
                ),
                ProjectMemberships.state == "allow",
            )
            .exists()
        )

        # Final query: only return active projects with no deny and at least one allow
        allowed_projects = (
            db_session.query(cls)
            .filter(
                cls.is_active == True,
                not_(deny_subquery),  # nothing denies access
                allow_subquery,  # something allows access
            )
            .all()
        )

        return {project.id for project in allowed_projects}


class ProjectMemberships(BaseModel):
    __tablename__ = "project_memberships"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    identity_type = db.Column(IdentityName, nullable=False)
    identity_name = db.Column(db.String(255), nullable=False)
    state = db.Column(MembershipState, nullable=False)
    project = relationship("Projects", back_populates="memberships")


class TargetNodeSessions(BaseModel):
    __tablename__ = "target_node_sessions"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    created_on = db.Column(db.DateTime, nullable=False)
    deactivated_on = db.Column(db.DateTime)  # Timestamp when session was deleted
    deactivated_by = db.Column(db.String(255))
    stack_name = db.Column(db.String(255))  # Name of the CloudFormation Stack
    session_name = db.Column(
        db.String(255), nullable=False
    )  # Session name specified by the user
    session_owner = db.Column(
        db.String(255), nullable=False, index=True
    )  # Session owner
    session_project = db.Column(db.String(255), nullable=False)  # Project
    session_state = db.Column(SessionState, nullable=False)
    session_state_latest_change_time = db.Column(db.DateTime, nullable=False)
    schedule = db.Column(db.Text, nullable=False)  #  session schedule
    session_thumbnail = db.Column(db.Text)  # session screenshot
    session_connection_instructions = db.Column(
        db.Text, nullable=False
    )  # Helper for the end user: e.g: SSH to this machine using the `qnxuser` user via ssh qnxuser@<ip>. Free-text admin-supplied; can hold multi-line instructions.
    session_uuid = db.Column(db.String(36), nullable=False, index=True)
    os_family = db.Column(OSFamily, nullable=False)
    # Instance Specific
    instance_state = db.Column(
        db.String(255), nullable=False
    )  # (pending/stopped/running)
    instance_private_ip = db.Column(db.String(255))  # Private IP of the EC2 host
    instance_private_dns = db.Column(db.String(255))  # Private IP of the EC2 host
    instance_id = db.Column(db.String(255))  # Instance ID of the EC2 host
    instance_type = db.Column(
        db.String(255), nullable=False
    )  # Instance type of the EC2 host

    # Relationships
    target_node_software_stack = relationship(
        "TargetNodeSoftwareStacks", back_populates="target_node_sessions"
    )
    target_node_software_stack_id = db.Column(
        db.Integer,
        db.ForeignKey("target_node_software_stacks.id", ondelete="CASCADE"),
        nullable=False,
    )


class TargetNodeProfiles(BaseModel):
    __tablename__ = "target_node_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    profile_name = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.Text)
    pattern_allowed_instance_types = db.Column(
        db.Text, nullable=False
    )  # csv of instance type,family allowed. Wildcard supported.
    allowed_instance_types = db.Column(
        db.Text, nullable=False
    )  # json of all instance types based on pattern, grouped by arch
    allowed_subnet_ids = db.Column(
        db.Text, nullable=False
    )  # csv of approved subnet ids. Wildcard supported.
    max_root_size = db.Column(db.Integer, nullable=False)  # max root size in GB

    target_node_software_stacks = relationship(
        "TargetNodeSoftwareStacks", back_populates="profile"
    )


class TargetNodeSoftwareStacks(BaseModel):
    __tablename__ = "target_node_software_stacks"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stack_name = db.Column(db.Text, nullable=False)

    # AMI Information
    ami_id = db.Column(db.String(255), nullable=False)
    ami_arch = db.Column(db.String(255), nullable=False)
    ami_root_disk_size = db.Column(db.Integer, nullable=False)
    ami_user_data_variables = db.Column(
        db.Text
    )  # CSV list of variable that will be replaced in the user data if specified: myvar1=myvalue,myvar2=myvalue2
    ami_connection_string = db.Column(
        db.Text, nullable=False
    )  # Optional, can specify information. Support variable substitution such as Instance Private IP etc ..

    os_family = db.Column(OSFamily, nullable=False)  # OS Family (Windows or Linux)
    # Stack Info
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    deactivated_by = db.Column(db.String(255))
    deactivated_on = db.Column(db.DateTime)
    thumbnail = db.Column(db.Text, nullable=False)
    description = db.Column(
        db.String(500)
    )  # Admin can add useful information to the user, such as who own the software stack or support email
    launch_tenancy = db.Column(db.String(255), nullable=False)
    launch_host = db.Column(db.String(255), nullable=True)

    # Parent Profile
    target_node_profile_id = Column(
        Integer, ForeignKey("target_node_profiles.id"), nullable=False
    )
    profile = relationship(
        "TargetNodeProfiles", back_populates="target_node_software_stacks"
    )

    # Parent User Data
    target_node_user_data_id = Column(
        Integer, ForeignKey("target_node_user_data.id"), nullable=False
    )

    user_data = relationship(
        "TargetNodeUserData", back_populates="target_node_software_stacks"
    )

    # Parent Sessions
    target_node_sessions = relationship(
        "TargetNodeSessions",
        back_populates="target_node_software_stack",
        cascade="all, delete-orphan",
    )

    # Parent Project
    projects = relationship(
        "Projects",
        secondary=project_target_node_software_stack_association,
        back_populates="target_node_software_stacks",
    )

    def as_dict(self, exclude_columns=None, allowed_project_ids=None):
        exclude_columns = exclude_columns or []
        result = super().as_dict(exclude_columns=exclude_columns)

        if self.projects:
            filtered_projects = (
                [p for p in self.projects if p.id in allowed_project_ids]
                if allowed_project_ids
                else self.projects
            )

            result["projects"] = [
                {
                    column.name: getattr(p, column.name)
                    for column in p.__table__.columns
                    if column.name not in exclude_columns
                }
                for p in filtered_projects
            ]
            result["allowed_aws_budgets"] = list(
                dict.fromkeys(p.aws_budget for p in filtered_projects)
            )
            result["allowed_projects"] = list(
                dict.fromkeys(p.project_name for p in filtered_projects)
            )
        else:
            result["projects"] = []
            result["allowed_aws_budgets"] = []
            result["allowed_projects"] = []

        if self.profile:
            result["profile"] = {
                column.name: getattr(self.profile, column.name)
                for column in self.profile.__table__.columns
                if column.name not in exclude_columns
            }
        else:
            result["profile"] = {}

        if self.user_data:
            user_data_fields = {
                "created_on": self.user_data.created_on,
                "created_by": self.user_data.created_by,
                "is_active": self.user_data.is_active,
                "template_name": self.user_data.template_name,
                "user_data": self.user_data.user_data,
                "description": self.user_data.description,
                "id": self.user_data.id,
            }
            result["user_data"] = {
                k: v for k, v in user_data_fields.items() if k not in exclude_columns
            }
        else:
            result["user_data"] = {}

        return result


class TargetNodeUserData(BaseModel):
    __tablename__ = "target_node_user_data"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    template_name = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.String(500))
    user_data = db.Column(db.Text)
    target_node_software_stacks = relationship(
        "TargetNodeSoftwareStacks",
        back_populates="user_data",
        cascade="all, delete-orphan",
        foreign_keys=[TargetNodeSoftwareStacks.target_node_user_data_id],
    )

    def as_dict(self, exclude_columns=None):
        result = super().as_dict(exclude_columns=exclude_columns)
        if self.target_node_software_stacks:
            # statically defined to avoid circular dependency if calling target_node_software_stacks.as_dict() via python object
            result["target_node_software_stacks"] = [
                {
                    column.name: getattr(stack, column.name)
                    for column in stack.__table__.columns
                }
                for stack in self.target_node_software_stacks
            ]

        else:
            result["target_node_software_stacks"] = []

        return result


class HardwareProfiles(BaseModel):
    """Admin-defined container that bundles capability sub-profiles.

    Exactly one HardwareProfile is effective per VDI launch (Project binding
    overrides Stack binding). Phase 1 registers a single sub-profile type --
    usb (boot-time). Future types (disk, cpu -- provision-time) add their own
    nullable FK column here plus a service-layer sub-profile type-registry
    entry; no churn to existing rows.
    """

    __tablename__ = "hardware_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    profile_name = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.String(500))

    # Per-type sub-profile reference (at most one per type by construction).
    # Phase 1: usb only. NULL = this profile carries no USB allowlist.
    usb_profile_id = db.Column(
        db.Integer,
        ForeignKey("usb_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    usb_profile = relationship("UsbProfiles", back_populates="hardware_profiles")
    software_stacks = relationship(
        "SoftwareStacks", back_populates="hardware_profile"
    )
    projects = relationship("Projects", back_populates="hardware_profile")


class UsbProfiles(BaseModel):
    """Reusable, named USB device allowlist (a DCV usb-devices.conf filter set).

    Referenced by zero or more HardwareProfiles. Its entries render to
    usb-devices.conf filter strings that the VDI boot hook writes before the
    DCV server starts.
    """

    __tablename__ = "usb_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    profile_name = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.String(500))

    # Relationships
    entries = relationship(
        "UsbProfileEntries",
        back_populates="usb_profile",
        cascade="all, delete-orphan",
    )
    hardware_profiles = relationship(
        "HardwareProfiles", back_populates="usb_profile"
    )


class UsbProfileEntries(BaseModel):
    """One DCV USB device filter string within a UsbProfile.

    DCV usb-devices.conf line format (8 comma-separated fields):
        Name, BaseClass, SubClass, Protocol, VID, PID, SupportAutoshare, SkipReset
    The class triple and VID/PID accept the literal "*" wildcard, so they are
    stored as String (not Integer) and validated on write and again on render.
    This is a device compatibility filter, NOT a security boundary.
    """

    __tablename__ = "usb_profile_entries"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    usb_profile_id = db.Column(
        db.Integer,
        ForeignKey("usb_profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)

    # Field 1: human label. Validated to contain no comma / newline / control
    # chars so it cannot break the line format or inject an extra line.
    device_label = db.Column(db.String(255), nullable=False)

    # Fields 2-6: USB class triple + ids. Integer value or the literal "*"
    # wildcard, stored as String. Validated: base_class/sub_class/protocol in
    # 0-255 or "*"; vid/pid in 0-65535 or "*".
    base_class = db.Column(db.String(8), nullable=False)
    sub_class = db.Column(db.String(8), nullable=False)
    protocol = db.Column(db.String(8), nullable=False)
    vid = db.Column(db.String(8), nullable=False)
    pid = db.Column(db.String(8), nullable=False)

    # Fields 7-8: behavior flags, rendered as 0/1.
    support_autoshare = db.Column(db.Boolean, nullable=False, default=True)
    skip_reset = db.Column(db.Boolean, nullable=False, default=False)

    # Admin-facing controls (never rendered to usb-devices.conf or end users):
    # enabled=False retains the row for documentation but excludes it from the
    # delivered allowlist (both the resolver Lambda and the preview skip it).
    # admin_comment is an internal operator note only.
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    admin_comment = db.Column(db.String(512), nullable=True)

    # Relationships
    usb_profile = relationship("UsbProfiles", back_populates="entries")

    def render_filter_line(self) -> str:
        """Render this entry as a DCV usb-devices.conf filter string.

        OS-agnostic: identical on Linux and Windows; only the target file path
        differs (owned by the boot hook).
        """
        return "{label},{bc},{sc},{proto},{vid},{pid},{auto},{reset}".format(
            label=self.device_label,
            bc=self.base_class,
            sc=self.sub_class,
            proto=self.protocol,
            vid=self.vid,
            pid=self.pid,
            auto=1 if self.support_autoshare else 0,
            reset=1 if self.skip_reset else 0,
        )


# --- Golden Image / Owned-Base AMI lineage ---

BaseImageStatus = ENUM(
    "pending", "copying", "active", "failed", name="base_image_status"
)


class BaseImageRegistry(BaseModel):
    """Owned-base AMI lineage registry. One row per (source_ami_id, region).

    Launch resolver returns owned_ami_id when status='active', else the source AMI id.
    base_os/arch are descriptive (from region_map.d) for reporting + manifest, not the lookup key.
    """

    __tablename__ = "base_image_registry"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # Descriptive identity (from region_map.d)
    base_os = db.Column(db.String(64), nullable=False)
    arch = db.Column(db.String(32), nullable=False)
    region = db.Column(db.String(32), nullable=False, index=True)

    # Lineage provenance: 'aws-base' (home copy) | 'xregion:<home_region>' (spoke)
    origin = db.Column(db.String(64), nullable=False, default="aws-base")

    # Source (what we copy FROM)
    source_alias = db.Column(db.String(255))  # SSM alias if alias-backed
    source_ami_id = db.Column(db.String(255), nullable=False, index=True)  # resolved concrete id; lookup key
    source_region = db.Column(db.String(32), nullable=False)
    source_owner = db.Column(db.String(32))  # DescribeImages OwnerId at discovery
    source_deprecation_time = db.Column(db.DateTime)  # AWS DeprecationTime of the source

    # Owned copy (what launches resolve TO)
    owned_ami_id = db.Column(db.String(255))
    status = db.Column(BaseImageStatus, nullable=False, default="pending", index=True)
    last_error = db.Column(db.Text)

    # Lifecycle
    auto_refresh = db.Column(db.Boolean, nullable=False, default=True)
    ref_count = db.Column(db.Integer, nullable=False, default=0)
    source_resolved_at = db.Column(db.DateTime)
    copying_since = db.Column(db.DateTime)  # when the row was claimed for copy; drives stuck-copy recovery
    copied_at = db.Column(db.DateTime)
    created_on = db.Column(db.DateTime, nullable=False, default=func.now())
    created_by = db.Column(db.String(255))

    __table_args__ = (
        db.UniqueConstraint(
            "source_ami_id", "region", name="uq_base_image_source_region"
        ),
    )


class VdiSavedImages(BaseModel):
    # Saved Desktops (Resume-From) registry. One row per captured image.
    __tablename__ = "vdi_saved_images"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Nullable: a stop-then-image capture inserts the row in 'pending_capture'
    # BEFORE the AMI exists (the box is stopping first for a clean, consistent
    # snapshot); the reconciler stamps image_id once CreateImage runs on the
    # stopped instance.
    image_id = db.Column(db.String(64), nullable=True, index=True)  # ami-...
    # Instance being captured, retained while state='pending_capture' so the
    # reconciler can wait-for-stopped -> CreateImage -> terminate it.
    capture_instance_id = db.Column(db.String(64))
    # Origin session's CFN stack, retained so the orphan-stack reaper does not
    # tear the box down (terminating it) before the deferred capture images it.
    capture_stack_name = db.Column(db.String(255))
    origin_session_uuid = db.Column(db.String(36))
    session_name = db.Column(db.String(255), nullable=False)
    os_family = db.Column(db.String(16), nullable=False)  # windows | linux
    base_os = db.Column(db.String(64))  # origin instance_base_os (for edh:DCVSystem tag on resume)
    software_stack_id = db.Column(db.Integer)  # origin software stack id (reused for the resumed session row)
    instance_type = db.Column(db.String(64), nullable=False)
    root_bytes = db.Column(db.BigInteger, default=0)
    software_stack_label = db.Column(db.String(255))
    created_on = db.Column(db.DateTime, nullable=False, default=func.now())
    capture_completed_at = db.Column(db.DateTime)  # stamped once when state flips capturing -> available
    created_by = db.Column(db.String(255), nullable=False)  # immutable creator
    owner = db.Column(db.String(255), nullable=False, index=True)  # current owner (reassignable)
    source = db.Column(db.String(16), nullable=False, default="save")  # save | interrupt
    state = db.Column(
        db.String(16), nullable=False, default="capturing"
    )  # pending_capture | capturing | available | resuming | consumed | error | recycled
    pinned = db.Column(db.Boolean, nullable=False, default=False, server_default="false")
    expires_at = db.Column(db.DateTime)
    deleted_on = db.Column(db.DateTime)  # set when soft-deleted (state=recycled); reaper hard-deletes after recycle TTL
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default="true")
    __table_args__ = (
        # One active saved image per origin session; makes the capture insert idempotent.
        db.Index(
            "uq_vdi_saved_active_session",
            "origin_session_uuid",
            unique=True,
            postgresql_where=text("state != 'consumed' AND is_active = true"),
        ),
    )


class GoldenImageNomination(BaseModel):
    """Tracks nominations of saved VDI images as golden image candidates."""
    __tablename__ = "golden_image_nominations"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    saved_image_id = db.Column(db.Integer, nullable=False, index=True)
    ami_id = db.Column(db.String(255), nullable=False)  # holds ami-id or SSM alias path
    nominated_by = db.Column(db.String(255), nullable=False, index=True)
    nominated_at = db.Column(db.DateTime, nullable=False, default=func.now())
    label = db.Column(db.String(500), nullable=False)
    os_family = db.Column(db.String(16), nullable=False)
    base_os = db.Column(db.String(64))
    arch = db.Column(db.String(16))
    status = db.Column(
        db.String(16), nullable=False, default="pending"
    )  # pending | approved | rejected | published
    reviewed_by = db.Column(db.String(255))
    reviewed_at = db.Column(db.DateTime)
    rejection_note = db.Column(db.String(500))
    target_stack_id = db.Column(db.Integer)
    target_stack_name = db.Column(db.String(255))


class SoftwareStackVersion(BaseModel):
    """Version history for published golden images per software stack."""
    __tablename__ = "software_stack_versions"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stack_id = db.Column(db.Integer, db.ForeignKey("software_stacks.id"), nullable=False, index=True)
    version = db.Column(db.Integer, nullable=False)
    ami_id = db.Column(db.String(255), nullable=False)  # holds ami-id or SSM alias path
    source_ami_id = db.Column(db.String(255))
    owned_ami_id = db.Column(db.String(255))
    published_by = db.Column(db.String(255), nullable=False)
    published_at = db.Column(db.DateTime, nullable=False, default=func.now())
    description = db.Column(db.String(500))
    nomination_id = db.Column(db.Integer)
    sysprep_status = db.Column(
        db.String(32), nullable=False, default="skipped_linux"
    )  # verified_clean | auto_sysprepped | skipped_linux | skipped_dedicated
    lineage_status = db.Column(
        db.String(16), nullable=False, default="not_needed"
    )  # copying | owned | copy_failed | not_needed
    validation_status = db.Column(
        db.String(16), nullable=False, default="skipped"
    )  # pending | passed | failed | skipped
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default="true")
    prior_ami_id = db.Column(db.String(255))
    failure_reason = db.Column(db.String(1000))
    __table_args__ = (
        db.UniqueConstraint("stack_id", "version", name="uq_stack_version"),
    )
