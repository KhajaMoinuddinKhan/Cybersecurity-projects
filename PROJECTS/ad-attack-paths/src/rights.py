"""What each Active Directory right actually grants.

A graph is only as good as the meaning of its edges, and the meaning here is domain
knowledge rather than anything the collector states. An entry saying ``GenericAll``
does not say "this is an attack path"; it says that the principal named in it can do
anything to the object it sits on, and the consequence of that is a fact about
Active Directory.

This is the same kind of table as the CVSS weights or the CIS control numbers in the
other projects: a published specification, written down once, so that every part of
the tool agrees about it and a reader can check it. What it is *not* is a list of
answers -- nothing here says which paths exist in a given directory, and none of it
is derived from the sample data.

The direction of every right is principal-to-object, because that is how an attacker
moves: controlling the principal reaches the object. The two exceptions are marked,
and both are the same idea in reverse -- controlling the *object* yields the
principal, which is what a session on a machine is.

Source: the SharpHound edge set, as documented by SpecterOps, and the underlying
Active Directory rights each one corresponds to.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Right", "RIGHTS", "CAPABILITIES", "right_for", "is_traversable",
           "capability_of", "EDGE_KINDS"]

# What a right lets an attacker do, as a class rather than a number. The classes are
# ordered by how directly they give control, and the order comes from the semantics
# below rather than from a weight anybody chose.
CAPABILITIES = (
    "control",       # directly gives full control of the target
    "credential",    # yields the target's secrets, so its identity
    "membership",    # places the principal inside a group, inheriting its rights
    "delegation",    # lets the principal act as another identity
    "session",       # yields the identity of whoever is logged in
    "access",        # gets onto the target machine
)


@dataclass(frozen=True)
class Right:
    """One right, what it grants, and how it is traversed."""

    name: str
    capability: str
    traverses: str = "forward"      # "forward" principal->object, "reverse" object->principal
    note: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "capability": self.capability,
                "traverses": self.traverses, "note": self.note}


# Every right the collector emits, with what it means. A right that appears in data
# and not here is reported rather than silently dropped -- see `capability_of`.
RIGHTS = (
    # --- full control of the target ------------------------------------------
    Right("GenericAll", "control",
          note="write every attribute, including the ones that grant rights"),
    Right("GenericWrite", "control",
          note="write any non-protected attribute; enough to set a logon script or "
               "an SPN, and enough to take the account over"),
    Right("WriteDacl", "control",
          note="rewrite the object's permissions, so grant yourself anything"),
    Right("WriteOwner", "control",
          note="make yourself the owner, and an owner may rewrite the permissions"),
    Right("Owns", "control",
          note="already the owner, which is WriteOwner without the step"),
    Right("AllExtendedRights", "control",
          note="every extended right on the object, which includes ForceChangePassword "
               "and, on a domain, replication"),
    Right("ForceChangePassword", "control",
          note="reset the account's password without knowing the old one"),
    Right("AddKeyCredentialLink", "control",
          note="attach a key credential, which is a shadow credential: authenticate "
               "as the account without changing its password"),
    Right("WriteAccountRestrictions", "control",
          note="write the account restrictions, which includes the delegation flags"),
    Right("WriteSPN", "control",
          note="set a service principal name, which makes the account kerberoastable"),
    Right("WriteGPLink", "control",
          note="link a policy to an organisational unit"),

    # --- the target's secrets ------------------------------------------------
    Right("GetChanges", "credential",
          note="replicate directory changes; with GetChangesAll this is DCSync"),
    Right("GetChangesAll", "credential",
          note="replicate all changes, which is the other half of DCSync"),
    Right("GetChangesInFilteredSet", "credential",
          note="replicate a filtered set, which is partial DCSync"),
    Right("DCSync", "credential",
          note="the collector's shorthand for GetChanges with GetChangesAll"),
    Right("SyncLAPSPassword", "credential",
          note="replicate the local administrator password of the target"),
    Right("ReadLAPSPassword", "credential",
          note="read the local administrator password stored in the directory"),
    Right("ReadGMSAPassword", "credential",
          note="read a group managed service account's password, which is the "
               "account's identity"),
    Right("ReadMSAPassword", "credential",
          note="read a managed service account's password"),
    Right("GMSAPassword", "credential",
          note="the group managed service account password, which is the "
               "account's identity rather than a credential it holds"),

    # --- membership ----------------------------------------------------------
    Right("MemberOf", "membership", traverses="forward",
          note="the principal is in the group, so it holds every right the group holds"),
    Right("AddMember", "membership",
          note="add a principal to the group, which is control of the group by "
               "another route"),
    Right("AddSelf", "membership",
          note="add yourself to the group"),
    Right("HasSIDHistory", "membership", traverses="reverse",
          note="the principal's token carries this SID, so it already has the "
               "history object's rights. Traversed in reverse: controlling the "
               "object that holds the SID history is controlling the principal"),

    # --- delegation ----------------------------------------------------------
    Right("AllowedToDelegate", "delegation",
          note="constrained delegation: ask for a service ticket to the target"),
    Right("AllowedToAct", "delegation",
          note="resource-based constrained delegation: write the target's "
               "msDS-AllowedToActOnBehalfOfOtherIdentity"),
    Right("AllowedToActOnBehalfOfOtherIdentity", "delegation",
          note="resource-based constrained delegation: the target may act on behalf of "
               "whatever identity is named in this attribute, so writing it is taking "
               "the target over"),
    Right("CoerceToTGT", "delegation",
          note="coerce the target into requesting a ticket-granting ticket, which can "
               "then be relayed to the target"),

    # --- sessions ------------------------------------------------------------
    Right("HasSession", "session", traverses="reverse",
          note="the principal is logged in on this machine. Traversed in reverse: "
               "compromising the machine yields the principal's credentials, which "
               "is the whole reason a session is worth finding"),

    # --- access to a machine -------------------------------------------------
    Right("AdminTo", "access", note="local administrator on the machine"),
    Right("CanPSRemote", "access", note="may open a PowerShell remote session"),
    Right("CanRDP", "access", note="may open a remote desktop session"),
    Right("ExecuteDCOM", "access", note="may invoke a DCOM object, which executes code"),
    Right("SQLAdmin", "access", note="administrator on the instance's SQL Server"),
    Right("RemoteInteractiveLogonRight", "access",
          note="may log on interactively over the network, which is remote desktop by "
               "another name"),
    Right("ExecuteCommand", "access",
          note="may execute a command on the host"),
    Right("DumpSMSAPassword", "credential",
          note="read the standalone managed service account's password, which is the "
               "account's identity"),

    # --- certificate services -------------------------------------------------
    # A certificate authority that will issue a certificate for any principal is a
    # route to domain control: the certificate authenticates as the principal it
    # names. These appear on certificate templates and authorities, and they are a
    # right rather than a path in exactly the way GenericAll is.
    Right("Enroll", "control",
          note="enrol for a certificate from this template. If the template permits "
               "a subject alternative name, the certificate can name any principal"),
    Right("ManageCA", "control",
          note="administer the certificate authority, which includes editing its "
               "configuration and restarting it"),
    Right("ManageCertificates", "control",
          note="approve pending certificate requests, which turns a request that "
               "needs approval into a certificate"),
    Right("ReadCA", "access",
          note="read the certificate authority's configuration"),

    # --- container and policy ------------------------------------------------
    Right("Contains", "membership",
          note="the container holds the object, which is not a right but is how a "
               "policy reaches everything inside it"),
    Right("GPLink", "control",
          note="link a policy to a container, so everything inside the container "
               "receives whatever the policy sets"),
    Right("TrustedBy", "control", traverses="reverse",
          note="the target trusts this domain. Recorded as context rather than walked: "
               "a trust permits authentication across it and does not grant control of "
               "anything"),
)

RIGHTS_BY_NAME = {}
for _right in RIGHTS:
    # the first definition wins, so a duplicate name cannot silently change meaning
    RIGHTS_BY_NAME.setdefault(_right.name.lower(), _right)


def right_for(name: str) -> Right | None:
    return RIGHTS_BY_NAME.get(str(name or "").strip().lower())


def capability_of(name: str) -> str | None:
    """What a right grants, or None when the right is not one this knows.

    None is a real answer and is reported rather than dropped: a directory may carry
    a right this table has never seen, and treating an unknown right as harmless is
    the same mistake as treating an unread rule as clear.
    """
    right = right_for(name)
    return right.capability if right else None


def is_traversable(name: str) -> bool:
    """Whether a right on its own moves an attacker from the principal to the object."""
    return right_for(name) is not None


EDGE_KINDS = ("ace", "membership", "session", "trust", "containment")
