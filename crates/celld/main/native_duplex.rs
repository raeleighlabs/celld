use super::*;

pub(super) async fn accept(
    mut request: Request<Incoming>,
    app: AppHandle,
    mut drain: watch::Receiver<bool>,
) -> HttpReply {
    use celld::native_duplex::CONNECT_DEADLINE;

    if !valid_connect(&request) {
        return response(StatusCode::BAD_REQUEST, "invalid private duplex CONNECT");
    }
    if *drain.borrow() {
        return response(StatusCode::SERVICE_UNAVAILABLE, "node draining");
    }
    // Only the handshake is a public admission. Retaining it in the pump
    // would block the ReleaseAll step that revokes native socket leases.
    let Some(_admission) = app.admit_public() else {
        return response(StatusCode::SERVICE_UNAVAILABLE, "node draining");
    };
    let services = celld::asyncrt::services();
    let mut credentials = request
        .headers()
        .get_all(hyper::header::AUTHORIZATION)
        .iter();
    let token = credentials
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if credentials.next().is_some() {
        return response(StatusCode::FORBIDDEN, "invalid duplex capability");
    }
    let Some(token) = token else {
        return response(StatusCode::FORBIDDEN, "invalid duplex capability");
    };
    let (capability, permit) = match services.duplex().take_admitted(token) {
        Ok(admitted) => admitted,
        Err(celld::native_duplex::DuplexAdmissionError::InvalidCapability) => {
            return response(StatusCode::FORBIDDEN, "invalid duplex capability");
        }
        Err(celld::native_duplex::DuplexAdmissionError::Capacity) => {
            return response(StatusCode::SERVICE_UNAVAILABLE, "duplex capacity exhausted");
        }
    };
    let target = capability.target;
    let allocation_revoked = target.revoked.clone();
    let owner_revoked = capability.owner.revocation();
    let opening = async {
        // Admission registers before routing's first await. The lease travels
        // through connect, response upgrade and the pump, never through an event.
        let lease = celld::native_ws::NativeLease::admit(
            &app,
            celld::ws_registry::ws_next_id(),
            &target.scope,
            None,
            capability.owner,
        )
        .await?;
        let revoked = lease.revocation();
        let engine = celld::container::engine_if_ready()
            .ok_or_else(|| anyhow::anyhow!("allocation engine unavailable"))?;
        let address = engine.allocation_duplex_address(&target)?;
        let stream = celld::asyncrt::select! {
            _ = revoked.cancelled() => anyhow::bail!("duplex admission revoked"),
            result = tokio::net::TcpStream::connect(address) => result?,
        };
        // Refuse a completed connect whose authority changed while it awaited.
        engine.allocation_duplex_address(&target)?;
        anyhow::ensure!(!revoked.is_cancelled(), "duplex admission revoked");
        Ok::<_, anyhow::Error>((lease, stream))
    };
    let opened = celld::asyncrt::select! {
        _ = drain.changed() => return response(StatusCode::SERVICE_UNAVAILABLE, "node draining"),
        _ = owner_revoked.cancelled() => return response(StatusCode::FORBIDDEN, "duplex activation retired"),
        _ = allocation_revoked.cancelled() => return response(StatusCode::FORBIDDEN, "duplex allocation retired"),
        result = tokio::time::timeout(CONNECT_DEADLINE, opening) => result,
    };
    let (lease, stream) = match opened {
        Ok(Ok(opened)) => opened,
        _ => return response(StatusCode::BAD_GATEWAY, "duplex connection failed"),
    };
    let upgrade = hyper::upgrade::on(&mut request);
    services.duplex().spawn(async move {
        let _permit = permit;
        let revoked = lease.revocation();
        let transport = async {
            let upgraded = tokio::time::timeout(CONNECT_DEADLINE, upgrade).await??;
            celld::native_duplex::pump(
                TokioIo::new(upgraded),
                stream,
                revoked.clone(),
                allocation_revoked.clone(),
            )
            .await
        };
        let _result = celld::asyncrt::select! {
            _ = drain.changed() => Ok(()),
            _ = revoked.cancelled() => Ok(()),
            _ = allocation_revoked.cancelled() => Ok(()),
            result = transport => result,
        };
        drop(lease);
    });
    let mut reply = response(StatusCode::OK, "");
    // RFC 9110 prohibits framing headers on a successful CONNECT.
    reply.headers_mut().remove(hyper::header::CONTENT_LENGTH);
    reply.headers_mut().remove(hyper::header::TRANSFER_ENCODING);
    reply
}

fn valid_connect<B>(request: &Request<B>) -> bool {
    !(request.method() != hyper::Method::CONNECT
        || request.version() != hyper::Version::HTTP_11
        || request.uri().authority().map(|value| value.as_str())
            != Some(celld::native_duplex::AUTHORITY)
        || request.uri().path_and_query().is_some()
        || request
            .headers()
            .contains_key(hyper::header::TRANSFER_ENCODING)
        || request
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .is_some_and(|value| value.as_bytes() != b"0")
        || request
            .headers()
            .get_all(hyper::header::CONTENT_LENGTH)
            .iter()
            .count()
            > 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_accepts_only_exact_authority_http11_and_no_framed_body() {
        let request = || {
            Request::builder()
                .method("CONNECT")
                .uri("celld-duplex:1")
                .body(())
                .unwrap()
        };
        assert!(valid_connect(&request()));
        for uri in [
            "example.com:443",
            "/celld-duplex:1",
            "http://celld-duplex:1/",
        ] {
            let mut changed = request();
            *changed.uri_mut() = uri.parse().unwrap();
            assert!(!valid_connect(&changed), "{uri}");
        }
        let mut changed = request();
        *changed.method_mut() = hyper::Method::GET;
        assert!(!valid_connect(&changed));
        let mut changed = request();
        *changed.version_mut() = hyper::Version::HTTP_10;
        assert!(!valid_connect(&changed));
        for (header, value) in [("content-length", "1"), ("transfer-encoding", "chunked")] {
            let changed = Request::builder()
                .method("CONNECT")
                .uri("celld-duplex:1")
                .header(header, value)
                .body(())
                .unwrap();
            assert!(!valid_connect(&changed), "{header}={value}");
        }
    }
}
