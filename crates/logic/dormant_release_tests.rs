use super::*;

fn config() -> Config {
    Config {
        max_resident: 1,
        max_activations: 1,
        max_evictions: 1,
        max_releases: 2,
        max_outbound_websockets: 1,
        ownership_on_evict: OwnershipOnEvict::Sticky,
        require_node_lease: false,
        peer_protocol: 1,
        operation_deadline_ms: Some(10),
        owner_log_recovery_backoff_ms: 1,
        owner_log_recovery_attempts: 1,
        alarm_resident_ms: 0,
        idle_evict_ms: None,
        pressure: pressure::PressureConfig::from_limits(None, Some(0)),
    }
}

#[test]
fn destructive_eviction_release_retry_does_not_repeat_local_retirement() {
    for deadline in [false, true] {
        let mut state = State::new("a", config());
        state.draining = true;
        let id = "Native:release-retry";
        let op = state.cell_op(id);
        let mut cell = Cell::default();
        set_phase(
            &mut state.occupied,
            &mut cell,
            Phase::Cleaning {
                op,
                epoch: 2,
                cause: StopCause::Evict { rebalance: true },
            },
        );
        state.cells.insert(id.into(), cell);
        state.eviction_permits.insert(id.into());
        let effects = on_event(&mut state, Event::RuntimeStopped { op });
        let release = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::ReleaseOwner { op, .. } => Some(*op),
                _ => None,
            })
            .unwrap();
        let effects = on_event(
            &mut state,
            if deadline {
                Event::TimerFired {
                    timer: Timer::OperationDeadline { op: release },
                    now_ms: 100,
                    now_mono_ms: 100,
                }
            } else {
                Event::OwnerReleased {
                    op: release,
                    result: Err(Failure::Ambiguous),
                }
            },
        );
        assert!(effects
            .iter()
            .any(|effect| matches!(effect, Effect::ReleaseOwner { .. })));
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, Effect::StopRuntime { .. })));
        assert_eq!(state.retiring_dormant(), 0);
        assert_eq!(state.releasing(), 1);
        state.validate().unwrap();
    }
}

#[test]
fn dormant_retirement_cannot_expire_or_restart_for_demand() {
    for draining in [false, true] {
        let mut state = State::new("a", config());
        for id in ["Native:a", "Native:b"] {
            state.cells.insert(
                id.into(),
                Cell {
                    phase: Phase::Dormant { epoch: 2 },
                    ..Cell::default()
                },
            );
        }
        let effects = on_event(
            &mut state,
            if draining {
                Event::ReleaseAll
            } else {
                Event::Rebalance { cells: 2 }
            },
        );
        let stops: Vec<_> = effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::StopRuntime {
                    op,
                    cell,
                    cause: StopCause::DormantRelease,
                    bounded: false,
                    ..
                } => Some((*op, cell.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(stops.len(), 2);
        assert_eq!(state.handoffs_in_flight(), 2);
        assert_eq!(state.occupied(), 0);
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, Effect::ReleaseOwner { .. })));
        state.validate().unwrap();
        for (op, id) in &stops {
            // Even a stale/injected deadline cannot turn partial local
            // retirement into owner release or a new activation.
            let effects = on_event(
                &mut state,
                Event::TimerFired {
                    timer: Timer::OperationDeadline { op: *op },
                    now_ms: 60_000,
                    now_mono_ms: 60_000,
                },
            );
            assert!(!effects.iter().any(|effect| matches!(
                effect,
                Effect::ReleaseOwner { .. } | Effect::StartRuntime { .. } | Effect::Restore { .. }
            )));
            let effects = on_event(
                &mut state,
                Event::Request {
                    request: *op + 100,
                    cell: id.clone(),
                },
            );
            assert!(!effects.iter().any(|effect| matches!(
                effect,
                Effect::AbandonEvictionStop { .. }
                    | Effect::StartRuntime { .. }
                    | Effect::Restore { .. }
            )));
            assert!(matches!(
                state.phase(id),
                Some(Phase::Cleaning {
                    cause: StopCause::DormantRelease,
                    ..
                })
            ));
            state.validate().unwrap();
        }
        for (op, _) in stops {
            let effects = on_event(&mut state, Event::RuntimeStopped { op });
            assert_eq!(
                effects
                    .iter()
                    .filter(|effect| matches!(effect, Effect::ReleaseOwner { .. }))
                    .count(),
                1
            );
            assert!(!effects.iter().any(|effect| matches!(
                effect,
                Effect::Restore { .. } | Effect::StartRuntime { .. }
            )));
            assert_eq!(state.handoffs_in_flight(), 2);
            state.validate().unwrap();
        }
    }
}
