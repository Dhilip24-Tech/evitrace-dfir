"""Z3 interval algebra with per-host clock-skew variables and unsat cores."""

from __future__ import annotations

import re
from dataclasses import dataclass

from z3 import And, ArithRef, Real, RealVal, Solver, sat, unsat

from evitrace.models import (
    CaseConfig,
    Claim,
    EventRecord,
    TemporalOutcome,
    TemporalProof,
)
from evitrace.store import host_skew

NAME_RE = re.compile(r"[^A-Za-z0-9_]")


def _name(value: str) -> str:
    return NAME_RE.sub("_", value)


def _seconds(value: float) -> str:
    return f"{value:.6f}"


@dataclass
class SolverModel:
    solver: Solver
    taus: dict[str, ArithRef]
    deltas: dict[str, ArithRef]
    constraints: dict[str, str]


def _build_model(events: list[EventRecord], config: CaseConfig) -> SolverModel:
    solver = Solver()
    taus: dict[str, ArithRef] = {}
    deltas: dict[str, ArithRef] = {}
    constraints: dict[str, str] = {}

    hosts = {event.host for event in events} | set(config.hosts)
    for host in sorted(hosts):
        delta = Real(f"delta_{_name(host)}")
        deltas[host] = delta
        skew = host_skew(config, host)
        name = f"skew_{_name(host)}"
        solver.assert_and_track(
            And(RealVal(_seconds(-skew)) <= delta, delta <= RealVal(_seconds(skew))), name
        )
        constraints[name] = f"clock offset for {host} stays within ±{skew:g}s"

    for event in events:
        tau = Real(f"tau_{_name(event.event_id)}")
        taus[event.event_id] = tau
        delta = deltas[event.host]
        earliest = event.earliest_utc.timestamp()
        latest = event.latest_utc.timestamp()
        name = f"bounds_{_name(event.event_id)}"
        solver.assert_and_track(
            And(
                RealVal(_seconds(earliest)) <= tau + delta,
                tau + delta <= RealVal(_seconds(latest)),
            ),
            name,
        )
        constraints[name] = f"{event.event_id} recorded interval [{earliest:.0f}, {latest:.0f}]"

    by_host: dict[str, list[EventRecord]] = {}
    for event in events:
        by_host.setdefault(event.host, []).append(event)

    for host, host_events in by_host.items():
        installs = [event for event in host_events if event.event_type == "os_install"]
        if installs:
            install = sorted(installs, key=lambda item: item.earliest_utc)[0]
            for event in host_events:
                if event.event_id == install.event_id:
                    continue
                name = f"precedence_os_{_name(install.event_id)}__{_name(event.event_id)}"
                solver.assert_and_track(
                    taus[install.event_id] < taus[event.event_id],
                    name,
                )
                constraints[name] = (
                    f"{install.event_id} (OS install) must precede {event.event_id} on {host}"
                )
        downloads = [event for event in host_events if event.event_type == "file_download"]
        processes = [event for event in host_events if event.event_type == "process_start"]
        for download in downloads:
            download_hash = str(download.fields.get("file_hash_sha256", ""))
            for process in processes:
                process_hash = str(process.fields.get("file_hash_sha256", ""))
                if download_hash and download_hash == process_hash:
                    name = f"precedence_dl_{_name(download.event_id)}__{_name(process.event_id)}"
                    solver.assert_and_track(
                        taus[download.event_id] < taus[process.event_id],
                        name,
                    )
                    constraints[name] = (
                        f"{download.event_id} (download) must precede "
                        f"{process.event_id} (execution) for the same hash"
                    )
    return SolverModel(solver=solver, taus=taus, deltas=deltas, constraints=constraints)


def verify_temporal(claim: Claim, events: list[EventRecord], config: CaseConfig) -> TemporalProof:
    if claim.temporal is None:
        return TemporalProof(
            outcome=TemporalOutcome.NOT_APPLICABLE,
            reason="claim has no temporal assertion",
        )
    by_id = {event.event_id: event for event in events}
    left = by_id.get(claim.temporal.left_event_id)
    right = by_id.get(claim.temporal.right_event_id)
    if left is None or right is None:
        missing = [
            event_id
            for event_id in (claim.temporal.left_event_id, claim.temporal.right_event_id)
            if event_id not in by_id
        ]
        return TemporalProof(
            outcome=TemporalOutcome.MISSING_EVENT,
            reason=f"temporal assertion cites missing event(s): {', '.join(missing)}",
        )

    # Scope the case model to the claim's relevant subgraph. A backdated event
    # elsewhere in the case must not poison unrelated claims.
    relevant: dict[str, EventRecord] = {left.event_id: left, right.event_id: right}
    for event in (left, right):
        if event.event_type in {"file_created", "os_install"}:
            for install in events:
                if install.host == event.host and install.event_type == "os_install":
                    relevant[install.event_id] = install
        if event.event_type in {"file_download", "process_start"}:
            file_hash = str(event.fields.get("file_hash_sha256", ""))
            if file_hash:
                for other in events:
                    if (
                        other.host == event.host
                        and str(other.fields.get("file_hash_sha256", "")) == file_hash
                        and other.event_type in {"file_download", "process_start"}
                    ):
                        relevant[other.event_id] = other

    model = _build_model(list(relevant.values()), config)
    tau_left = model.taus[left.event_id]
    tau_right = model.taus[right.event_id]

    model.solver.push()
    model.solver.assert_and_track(tau_left < tau_right, "claim_lt")
    check_lt = model.solver.check()
    core_lt = [str(item) for item in model.solver.unsat_core()] if check_lt == unsat else []
    model.solver.pop()

    model.solver.push()
    model.solver.assert_and_track(tau_left >= tau_right, "claim_ge")
    check_ge = model.solver.check()
    core_ge = [str(item) for item in model.solver.unsat_core()] if check_ge == unsat else []
    model.solver.pop()

    skew_left = host_skew(config, left.host)
    skew_right = host_skew(config, right.host)
    left_range = (
        left.earliest_utc.timestamp() - skew_left,
        left.latest_utc.timestamp() + skew_left,
    )
    right_range = (
        right.earliest_utc.timestamp() - skew_right,
        right.latest_utc.timestamp() + skew_right,
    )
    # For a shared clock the offset cancels, so compare recorded intervals. For
    # separate clocks the skew bounds widen each interval before comparison.
    if left.host == right.host:
        compare_left = (left.earliest_utc.timestamp(), left.latest_utc.timestamp())
        compare_right = (right.earliest_utc.timestamp(), right.latest_utc.timestamp())
    else:
        compare_left = left_range
        compare_right = right_range
    overlap = max(
        0.0, min(compare_left[1], compare_right[1]) - max(compare_left[0], compare_right[0])
    )

    sat_lt = check_lt == sat
    sat_ge = check_ge == sat
    if sat_lt and not sat_ge:
        outcome = TemporalOutcome.ENTAILED
        reason = (
            f"strict precedence holds in every valid clock model; "
            f"{left.host} skew cancels on the same host"
            if left.host == right.host
            else "strict precedence holds in every valid clock model"
        )
        core: list[str] = []
    elif sat_ge and not sat_lt:
        outcome = TemporalOutcome.UNSAT_CONFLICT
        reason = "the asserted order is impossible under the case bounds and axioms"
        core = core_lt
    elif sat_lt and sat_ge:
        outcome = TemporalOutcome.AMBIGUOUS_SKEW
        reason = (
            f"true ranges overlap by {overlap:.1f}s; both orders satisfy the case model "
            f"({left.host} ±{skew_left:g}s, {right.host} ±{skew_right:g}s)"
        )
        core = []
    else:
        outcome = TemporalOutcome.UNSAT_CONFLICT
        reason = (
            "both orders are impossible: the recorded timestamps contradict a case axiom "
            "(see unsat core)"
        )
        core = core_lt or core_ge

    return TemporalProof(
        outcome=outcome,
        sat_lt=sat_lt,
        sat_ge=sat_ge,
        left_range=left_range,
        right_range=right_range,
        overlap_seconds=round(overlap, 3) if outcome is TemporalOutcome.AMBIGUOUS_SKEW else None,
        unsat_core=core,
        reason=reason,
    )
