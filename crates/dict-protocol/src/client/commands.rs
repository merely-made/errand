//! Typed dictionary commands over the existing budgeted session.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout_at;

use super::{ClientError, Session, refused};
use crate::wire::{self, Database, Definition, Match, parse_definition_header};

impl<S> Session<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// `SHOW DB`: the databases this server offers.
    ///
    /// An empty list is a legitimate answer (`554 no databases present`), not
    /// an error.
    pub async fn databases(&mut self) -> Result<Vec<Database>, ClientError> {
        let deadline = self.begin_operation("SHOW DB")?;
        let result = timeout_at(deadline, self.databases_inner()).await;
        self.finish_operation(deadline, result)
    }

    async fn databases_inner(&mut self) -> Result<Vec<Database>, ClientError> {
        let status = self.send_command("SHOW DB").await?;
        match status.code {
            wire::DATABASES_FOLLOW => {
                let lines = self.read_text_block().await?;
                let databases = wire::parse_databases(&lines);
                self.expect_ok().await?;
                Ok(databases)
            }
            554 => Ok(Vec::new()),
            _ => Err(refused(status)),
        }
    }

    /// `SHOW STRAT`: the matching strategies this server supports.
    pub async fn strategies(&mut self) -> Result<Vec<Database>, ClientError> {
        let deadline = self.begin_operation("SHOW STRAT")?;
        let result = timeout_at(deadline, self.strategies_inner()).await;
        self.finish_operation(deadline, result)
    }

    async fn strategies_inner(&mut self) -> Result<Vec<Database>, ClientError> {
        let status = self.send_command("SHOW STRAT").await?;
        match status.code {
            wire::STRATEGIES_FOLLOW => {
                let lines = self.read_text_block().await?;
                let strategies = wire::parse_databases(&lines);
                self.expect_ok().await?;
                Ok(strategies)
            }
            555 => Ok(Vec::new()),
            _ => Err(refused(status)),
        }
    }

    /// `DEFINE database word`. Use `"*"` for every database, `"!"` for the
    /// first that matches.
    ///
    /// No match is an empty vector rather than an error: `552` means the word
    /// is absent, which is an answer.
    pub async fn define(
        &mut self,
        database: &str,
        word: &str,
    ) -> Result<Vec<Definition>, ClientError> {
        let line = self.parameter_command("DEFINE", &[database, word])?;
        let deadline = self.begin_operation(&line)?;
        let result = timeout_at(deadline, self.define_inner(&line)).await;
        self.finish_operation(deadline, result)
    }

    async fn define_inner(&mut self, line: &str) -> Result<Vec<Definition>, ClientError> {
        let status = self.send_command(line).await?;
        match status.code {
            wire::DEFINITIONS_FOLLOW => {}
            wire::NO_MATCH => return Ok(Vec::new()),
            _ => return Err(refused(status)),
        }

        // Then one 151-plus-text-block per definition, ending with a 250.
        let mut definitions = Vec::new();
        loop {
            let status = self.read_status().await?;
            match status.code {
                wire::DEFINITION_FOLLOWS => {
                    let Some((word, database, database_description)) =
                        parse_definition_header(&status)
                    else {
                        self.unusable = true;
                        return Err(ClientError::Protocol(format!(
                            "malformed 151: {}",
                            status.text
                        )));
                    };
                    definitions.push(Definition {
                        word,
                        database,
                        database_description,
                        text: self.read_text_block().await?,
                    });
                }
                code if (200..300).contains(&code) => return Ok(definitions),
                _ => return Err(refused(status)),
            }
        }
    }

    /// `MATCH database strategy word`.
    pub async fn matches(
        &mut self,
        database: &str,
        strategy: &str,
        word: &str,
    ) -> Result<Vec<Match>, ClientError> {
        let line = self.parameter_command("MATCH", &[database, strategy, word])?;
        let deadline = self.begin_operation(&line)?;
        let result = timeout_at(deadline, self.matches_inner(&line)).await;
        self.finish_operation(deadline, result)
    }

    async fn matches_inner(&mut self, line: &str) -> Result<Vec<Match>, ClientError> {
        let status = self.send_command(line).await?;
        match status.code {
            wire::MATCHES_FOLLOW => {
                let lines = self.read_text_block().await?;
                let matches = wire::parse_matches(&lines);
                self.expect_ok().await?;
                Ok(matches)
            }
            wire::NO_MATCH => Ok(Vec::new()),
            _ => Err(refused(status)),
        }
    }

    /// `CLIENT text`: announce who is calling. Servers log it; none require it.
    pub async fn announce(&mut self, text: &str) -> Result<(), ClientError> {
        self.check_command_parts(&["CLIENT ", text])?;
        let line = format!("CLIENT {text}");
        let deadline = self.begin_operation(&line)?;
        let result = timeout_at(deadline, self.success_command(&line)).await;
        self.finish_operation(deadline, result)
    }

    /// `QUIT`, consuming the session.
    pub async fn quit(mut self) -> Result<(), ClientError> {
        let deadline = self.begin_operation("QUIT")?;
        let result = timeout_at(deadline, self.success_command("QUIT")).await;
        self.finish_operation(deadline, result)
    }

    async fn success_command(&mut self, line: &str) -> Result<(), ClientError> {
        let status = self.send_command(line).await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(refused(status))
        }
    }
}
