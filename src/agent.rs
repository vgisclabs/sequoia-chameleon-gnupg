use anyhow::Result;

use sequoia_openpgp as openpgp;
use sequoia_ipc as ipc;
use openpgp::{
    crypto::{
        Password,
        mem::Protected,
    },
};
use ipc::{
    gnupg::Agent,
    assuan::{Response, escape},
};
use futures::stream::StreamExt;

/// Returns a convenient Err value for use in the state machines
/// below.
fn operation_failed<T>(message: &Option<String>) -> Result<T> {
    Err(ipc::gnupg::Error::OperationFailed(
        message.as_ref().map(|e| e.to_string())
            .unwrap_or_else(|| "Unknown reason".into()))
        .into())
}

/// Returns a convenient Err value for use in the state machines
/// below.
fn protocol_error<T>(response: &Response) -> Result<T> {
    Err(ipc::gnupg::Error::ProtocolError(
        format!("Got unexpected response {:?}", response))
        .into())
}

async fn acknowledge_inquiry(agent: &mut Agent) -> Result<()> {
    agent.send("END")?;
    agent.next().await; // Dummy read to send END.
    Ok(())
}

pub async fn send_simple<C>(agent: &mut ipc::gnupg::Agent, cmd: C)
                            -> Result<()>
where
    C: AsRef<str>,
{
    agent.send(cmd.as_ref())?;
    while let Some(response) = agent.next().await {
        match response? {
            Response::Ok { .. }
            | Response::Comment { .. }
            | Response::Status { .. } =>
                (), // Ignore.
            Response::Error { ref message, .. } =>
                return operation_failed(message),
            response =>
                return protocol_error(&response),
        }
    }

    Ok(())
}

/// Makes the agent ask for a password.
pub async fn get_passphrase<C, CS, ES, P>(agent: &mut ipc::gnupg::Agent,
                                          cache_id: C,
                                          err_msg: Option<ES>,
                                          prompt: Option<String>,
                                          desc_msg: Option<String>,
                                          newsymkey: bool,
                                          repeat: usize,
                                          check: bool,
                                          mut pinentry_cb: P)
                                          -> Result<Password>
where
    C: Into<Option<CS>>,
    CS: AsRef<str>,
    ES: AsRef<str>,
    P: FnMut(Vec<u8>),
{
    agent.send(format!(
        "GET_PASSPHRASE --data --repeat={}{}{} -- {} {} {} {}",
        repeat,
        if (repeat > 0 && check) || newsymkey { " --check" } else { "" },
        if newsymkey { " --newsymkey" } else { "" },
        cache_id.into().as_ref().map(escape).unwrap_or_else(|| "X".into()),
        err_msg.as_ref().map(escape).unwrap_or_else(|| "X".into()),
        prompt.as_ref().map(escape).unwrap_or_else(|| "X".into()),
        desc_msg.as_ref().map(escape).unwrap_or_else(|| "X".into()),
    ))?;

    let mut password = Vec::new();
    while let Some(response) = agent.next().await {
        match response? {
            Response::Ok { .. }
            | Response::Comment { .. }
            | Response::Status { .. } =>
                (), // Ignore.
            Response::Inquire { keyword, parameters } => {
                match keyword.as_str() {
                    "PINENTRY_LAUNCHED" =>
                        pinentry_cb(parameters.unwrap_or_default()),
                    _ => (),
                }
                acknowledge_inquiry(agent).await?;
            },
            Response::Data { partial } => {
                // Securely erase partial.
                let partial = Protected::from(partial);
                password.extend_from_slice(&partial);
            },
            Response::Error { ref message, .. } =>
                return operation_failed(message),
        }
    }
    let password = Password::from(password);

    Ok(password)
}

/// Makes the agent forget a password.
pub async fn forget_passphrase<C, P>(agent: &mut ipc::gnupg::Agent,
                                     cache_id: C,
                                     mut pinentry_cb: P)
                                     -> Result<()>
where
    C: AsRef<str>,
    P: FnMut(Vec<u8>),
{
    agent.send(format!("CLEAR_PASSPHRASE {}", escape(cache_id.as_ref())))?;
    while let Some(response) = agent.next().await {
        match response? {
            Response::Ok { .. }
            | Response::Comment { .. }
            | Response::Status { .. } =>
                (), // Ignore.
            Response::Inquire { keyword, parameters } => {
                match keyword.as_str() {
                    "PINENTRY_LAUNCHED" => {
                        pinentry_cb(parameters.unwrap_or_default());
                    },
                    _ => (),
                }
                acknowledge_inquiry(agent).await?
            },
            Response::Error { ref message, .. } =>
                return operation_failed(message),
            response =>
                return protocol_error(&response),
        }
    }
    Ok(())
}
