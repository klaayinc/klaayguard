use reqwest::{self, StatusCode};

pub async fn send_payload(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    body_json: Vec<u8>,
) -> Result<StatusCode, reqwest::Error> {
    let resp = client
        .post(format!("{}/klaayguard/data", base))
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, "application/vnd.api+json")
        .header(reqwest::header::ACCEPT, "application/vnd.api+json")
        .body(body_json)
        .send()
        .await?;
    Ok(resp.status())
}
