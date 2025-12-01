use console::style;
use solana_pubkey::Pubkey;

use crate::{
    commands::CommandExec,
    constants::lamports_to_sol,
    context::ScillaContext,
    error::ScillaResult,
    prompt::prompt_data,
    ui::show_spinner,
};

/// Commands related to wallet or account management
#[derive(Debug, Clone)]
pub enum AccountCommand {
    Fetch,
    Balance,
    Transfer,
    Airdrop,
    ConfirmTransaction,
    LargestAccounts,
    NonceAccount,
    GoBack,
}

impl AccountCommand {
    pub fn description(&self) -> &'static str {
        match self {
            AccountCommand::Fetch => "Fetch Account info",
            AccountCommand::Balance => "Get Account Balance",
            AccountCommand::Transfer => "Transfer SOL",
            AccountCommand::Airdrop => "Request Airdrop",
            AccountCommand::ConfirmTransaction => "Confirm a pending transaction",
            AccountCommand::LargestAccounts => "Fetch cluster’s largest accounts",
            AccountCommand::NonceAccount => "Inspect or manage nonce accounts",
            AccountCommand::GoBack => "Go back",
        }
    }
}

impl AccountCommand {
    pub async fn process_command(&self, ctx: &ScillaContext) -> ScillaResult<()> {
        match self {
            AccountCommand::Fetch => {
                let pubkey: Pubkey = prompt_data("Enter Pubkey :")?;
                show_spinner(self.description(), fetch_acc_data(ctx, &pubkey)).await?;
            }
            AccountCommand::Balance => {
                let pubkey: Pubkey = prompt_data("Enter Pubkey :")?;
                show_spinner(self.description(), fetch_account_balance(ctx, &pubkey)).await?;
            }
            AccountCommand::Transfer => {
                show_spinner(self.description(), transfer_sol(ctx)).await?;
            }
            AccountCommand::Airdrop => {
                show_spinner(self.description(), request_sol_airdrop(ctx)).await?;
            }
            AccountCommand::ConfirmTransaction => {
                // show_spinner(self.description(), todo!()).await?;
            }
            AccountCommand::LargestAccounts => {
                // show_spinner(self.description(), todo!()).await?;
            }
            AccountCommand::NonceAccount => {
                // show_spinner(self.description(), todo!()).await?;
            }
            AccountCommand::GoBack => {
                return Ok(CommandExec::GoBack);
            }
        };

        Ok(CommandExec::Process(()))
    }
}

async fn request_sol_airdrop(ctx: &ScillaContext) -> anyhow::Result<()> {
    use anyhow::Context;
    
    let amount_sol: f64 = prompt_data("Enter amount in SOL to request:")
        .context("Failed to parse amount. Please enter a valid number.")?;
    
    if amount_sol <= 0.0 {
        return Err(anyhow::anyhow!("Amount must be positive. You entered: {} SOL", amount_sol));
    }
    
    let lamports = crate::constants::sol_to_lamports(amount_sol);
    if lamports == 0 {
        return Err(anyhow::anyhow!(
            "Amount too small. Minimum supported: 0.000000001 SOL (1 lamport)"
        ));
    }
    
    let sig = ctx.rpc().request_airdrop(ctx.pubkey(), lamports).await;
    match sig {
        Ok(signature) => {
            println!(
                "{} {}",
                style("Airdrop requested successfully!").green().bold(),
                style(format!("Signature: {signature}")).cyan()
            );
        }
        Err(err) => {
            let err_msg = format!("{}", err);
            eprintln!(
                "{} {}",
                style("Airdrop failed:").red().bold(),
                style(err_msg).red()
            );
            return Err(err.into());
        }
    }

    Ok(())
}

async fn fetch_acc_data(ctx: &ScillaContext, pubkey: &Pubkey) -> anyhow::Result<()> {
    let acc = ctx.rpc().get_account(pubkey).await?;

    println!(
        "{}\n{}",
        style("Account info:").green().bold(),
        style(format!("{acc:#?}")).cyan()
    );

    Ok(())
}

async fn fetch_account_balance(ctx: &ScillaContext, pubkey: &Pubkey) -> anyhow::Result<()> {
    let acc = ctx.rpc().get_account(pubkey).await?;
    let acc_balance: f64 = lamports_to_sol(acc.lamports);

    println!(
        "{}\n{}",
        style("Account balance in SOL:").green().bold(),
        style(format!("{acc_balance:#?}")).cyan()
    );

    Ok(())
}


/// Returns an error if:
/// - Destination is the same as sender (self-transfer)
/// - Amount is zero or negative
/// - Amount exceeds maximum supported value (u64::MAX lamports)
/// - Amount is too small (less than 1 lamport)
fn validate_transfer_params(
    sender: &Pubkey,
    destination: &Pubkey,
    amount_sol: f64,
) -> anyhow::Result<u64> {
    if destination == sender {
        return Err(anyhow::anyhow!(
            "Cannot send to self. Destination must be different from sender address."
        ));
    }

    if amount_sol <= 0.0 {
        return Err(anyhow::anyhow!("Amount must be positive. You entered: {} SOL", amount_sol));
    }

    const MAX_SOL: f64 = (u64::MAX as f64) / (crate::constants::LAMPORTS_PER_SOL as f64);
    if amount_sol > MAX_SOL {
        return Err(anyhow::anyhow!(
            "Amount too large. Maximum supported: {} SOL",
            MAX_SOL
        ));
    }

    let lamports = crate::constants::sol_to_lamports(amount_sol);

    if lamports == 0 {
        return Err(anyhow::anyhow!(
            "Amount too small. Minimum supported: 0.000000001 SOL (1 lamport)"
        ));
    }

    Ok(lamports)
}

/// Returns an error if balance is insufficient to cover transfer amount plus fees
fn validate_balance(
    balance_lamports: u64,
    transfer_lamports: u64,
    fee_lamports: u64,
) -> anyhow::Result<()> {
    let required = transfer_lamports.saturating_add(fee_lamports);
    if balance_lamports < required {
        return Err(anyhow::anyhow!(
            "Insufficient balance. Required: {} SOL (including {} SOL fee), Available: {} SOL",
            crate::constants::lamports_to_sol(required),
            crate::constants::lamports_to_sol(fee_lamports),
            crate::constants::lamports_to_sol(balance_lamports),
        ));
    }
    Ok(())
}



/// Returns an error if:
/// - RPC connection fails
/// - Failed to get recent blockhash
async fn build_transfer_transaction(
    ctx: &ScillaContext,
    destination: &Pubkey,
    lamports: u64,
) -> anyhow::Result<solana_sdk::transaction::Transaction> {
    use anyhow::Context;
    use solana_sdk::{message::Message, transaction::Transaction};
    use solana_system_interface::instruction;

    let transfer_instruction = instruction::transfer(ctx.pubkey(), destination, lamports);
    let recent_blockhash = ctx
        .rpc()
        .get_latest_blockhash()
        .await
        .context("Failed to get recent blockhash. Check your RPC connection.")?;

    let message = Message::new(std::slice::from_ref(&transfer_instruction), Some(ctx.pubkey()));
    let mut transaction = Transaction::new_unsigned(message);
    transaction.sign(&[ctx.keypair()], recent_blockhash);

    Ok(transaction)
}

async fn transfer_sol(ctx: &ScillaContext) -> anyhow::Result<()> {
    use anyhow::Context;
    use inquire::Confirm;

    let destination: Pubkey = prompt_data("Enter destination address:")
        .context("Failed to parse destination address. Please enter a valid Solana pubkey.")?;

    let amount_sol: f64 = prompt_data("Enter amount in SOL:")
        .context("Failed to parse amount. Please enter a valid number.")?;

    let lamports = validate_transfer_params(ctx.pubkey(), &destination, amount_sol)?;

    println!("\n{}", style("━".repeat(60)).dim());
    println!("{}", style("Simulating transaction...").dim());

    let test_transaction = build_transfer_transaction(ctx, &destination, lamports).await?;

    let simulation_result = ctx
        .rpc()
        .simulate_transaction(&test_transaction)
        .await
        .context("Failed to simulate transaction")?;

    const FALLBACK_FEE_LAMPORTS: u64 = 5_000;
    let actual_fee_lamports = simulation_result.value.fee.unwrap_or(FALLBACK_FEE_LAMPORTS);
    let actual_fee_sol = lamports_to_sol(actual_fee_lamports);

    if let Some(err) = &simulation_result.value.err {
        return Err(anyhow::anyhow!(
            "Transaction simulation failed: {:?}",
            err
        ));
    }

    // Check logs for critical error patterns (more specific than just "Error")
    if let Some(logs) = &simulation_result.value.logs {
        let critical_errors: Vec<String> = logs
            .iter()
            .filter(|log| {
                log.contains("Error:") || 
                log.contains("failed") || 
                log.contains("insufficient") ||
                log.contains("invalid")
            })
            .map(|s| s.clone())
            .collect();
        
        if !critical_errors.is_empty() {
            return Err(anyhow::anyhow!(
                "Transaction simulation detected errors:\n{}",
                critical_errors.join("\n")
            ));
        }
    }

    let current_balance = ctx
        .rpc()
        .get_balance(ctx.pubkey())
        .await
        .context("Failed to fetch current balance. Check your RPC connection.")?;

    validate_balance(current_balance, lamports, actual_fee_lamports)?;

    println!("\n{}", style("━".repeat(60)).dim());
    println!("{}", style("Transfer Confirmation").bold().cyan());
    println!("{}", style("━".repeat(60)).dim());
    println!(
        "{:<12} {}",
        style("From:").bold(),
        style(ctx.pubkey()).cyan()
    );
    println!(
        "{:<12} {}",
        style("To:").bold(),
        style(&destination).cyan()
    );
    println!(
        "{:<12} {} SOL ({} lamports)",
        style("Amount:").bold(),
        style(amount_sol).green(),
        style(lamports).dim()
    );
    println!(
        "{:<12} {} SOL",
        style("Current Balance:").bold(),
        style(lamports_to_sol(current_balance)).yellow()
    );
    println!(
        "{:<12} {} SOL",
        style("Fee (actual):").bold(),
        style(format!("{actual_fee_sol:.9}")).green()
    );
    println!(
        "{:<12} {} SOL",
        style("Balance after:").bold(),
        style(lamports_to_sol(current_balance.saturating_sub(lamports).saturating_sub(actual_fee_lamports))).cyan()
    );
    println!("{}\n", style("━".repeat(60)).dim());

    let confirmed = Confirm::new("Confirm transfer?")
        .with_default(false)
        .prompt()?;

    if !confirmed {
        println!("{}", style("Transfer cancelled").yellow());
        return Ok(());
    }

    println!("{}", style("Sending transaction...").dim());

    let transaction = build_transfer_transaction(ctx, &destination, lamports).await?;

    let signature = ctx
        .rpc()
        .send_and_confirm_transaction(&transaction)
        .await
        .with_context(|| {
            format!(
                "Transaction failed. Transfer of {} SOL from {} to {} could not be completed.",
                amount_sol, ctx.pubkey(), destination
            )
        })?;
    
    let new_balance = ctx
        .rpc()
        .get_balance(ctx.pubkey())
        .await
        .context("Transfer succeeded but failed to fetch updated balance.")?;

    println!("\n{}", style("Transfer successful!").green().bold());
    println!(
        "{:<15} {}",
        style("Signature:").bold(),
        style(&signature).cyan()
    );

    let explorer_url = get_explorer_url(&signature, ctx);
    println!(
        "{:<15} {}",
        style("Explorer:").bold(),
        style(&explorer_url).cyan().underlined()
    );

    println!(
        "{:<15} {} SOL",
        style("New Balance:").bold(),
        style(format!("{:.9}", lamports_to_sol(new_balance))).green()
    );

    Ok(())
}

fn get_network_cluster(rpc_url: &str) -> &str {
    let hostname = if let Some(start) = rpc_url.find("://") {
        let after_scheme = &rpc_url[start + 3..];
        if let Some(end) = after_scheme.find('/') {
            &after_scheme[..end]
        } else {
            after_scheme
        }
    } else {
        rpc_url
    };

    let host_only = if let Some(colon_pos) = hostname.find(':') {
        &hostname[..colon_pos]
    } else {
        hostname
    };

    if host_only.contains("mainnet-beta") {
        ""
    } else if host_only.contains("devnet") {
        "?cluster=devnet"
    } else if host_only.contains("testnet") {
        "?cluster=testnet"
    } else {
        "?cluster=custom"
    }
}

fn get_explorer_url(signature: impl std::fmt::Display, ctx: &ScillaContext) -> String {
    let rpc_url = ctx.rpc_url();
    let network = get_network_cluster(rpc_url);
    format!("https://explorer.solana.com/tx/{signature}{network}")
}

#[cfg(test)]
mod tests {
    use super::{get_network_cluster, validate_transfer_params, validate_balance};
    use std::str::FromStr;
    use solana_pubkey::Pubkey;

    fn test_sender() -> Pubkey {
        Pubkey::from_str("11111111111111111111111111111112").unwrap()
    }

    fn test_recipient() -> Pubkey {
        Pubkey::from_str("11111111111111111111111111111113").unwrap()
    }

    #[test]
    fn test_network_cluster_mainnet() {
        assert_eq!(get_network_cluster("https://api.mainnet-beta.solana.com"), "");
        assert_eq!(get_network_cluster("https://rpc.mainnet-beta.solana.com"), "");
    }

    #[test]
    fn test_network_cluster_devnet() {
        assert_eq!(
            get_network_cluster("https://api.devnet.solana.com"),
            "?cluster=devnet"
        );
    }

    #[test]
    fn test_network_cluster_testnet() {
        assert_eq!(
            get_network_cluster("https://api.testnet.solana.com"),
            "?cluster=testnet"
        );
    }

    #[test]
    fn test_network_cluster_custom() {
        assert_eq!(
            get_network_cluster("https://custom-rpc.example.com"),
            "?cluster=custom"
        );
        assert_eq!(
            get_network_cluster("http://localhost:8899"),
            "?cluster=custom"
        );
    }

    #[test]
    fn test_explorer_url_format() {
        let sig = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

        let mainnet_url = format!("https://explorer.solana.com/tx/{}{}", sig, get_network_cluster("https://api.mainnet-beta.solana.com"));
        assert_eq!(mainnet_url, format!("https://explorer.solana.com/tx/{sig}"));

        let devnet_url = format!("https://explorer.solana.com/tx/{}{}", sig, get_network_cluster("https://api.devnet.solana.com"));
        assert_eq!(devnet_url, format!("https://explorer.solana.com/tx/{sig}?cluster=devnet"));
    }



    #[test]
    fn test_network_cluster_edge_cases() {
        // Test edge cases for network detection
        assert_eq!(
            get_network_cluster("https://my-custom-rpc.com/mainnet-beta/path"),
            "?cluster=custom" // Hostname is my-custom-rpc.com, not mainnet-beta
        );

        assert_eq!(
            get_network_cluster("https://api.devnet.solana.com:8080"),
            "?cluster=devnet" // Should strip port before checking
        );

        assert_eq!(
            get_network_cluster("localhost:8899"),
            "?cluster=custom"
        );

        assert_eq!(
            get_network_cluster("https://api.mainnet-beta.solana.com"),
            ""
        );
        assert_eq!(
            get_network_cluster("https://rpc.mainnet-beta.solana.com"),
            ""
        );
    }

    #[test]
    fn test_validate_transfer_params_valid_transfer() {
        let sender = test_sender();
        let recipient = test_recipient();
        let amount = 1.5;

        let result = validate_transfer_params(&sender, &recipient, amount);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1_500_000_000); // 1.5 SOL in lamports
    }

    #[test]
    fn test_validate_transfer_params_self_transfer_rejected() {
        let sender = test_sender();

        let result = validate_transfer_params(&sender, &sender, 1.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cannot send to self"));
    }

    #[test]
    fn test_validate_transfer_params_negative_amount() {
        let sender = test_sender();
        let recipient = test_recipient();

        let result = validate_transfer_params(&sender, &recipient, -1.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Amount must be positive"));
    }

    #[test]
    fn test_validate_transfer_params_zero_amount() {
        let sender = test_sender();
        let recipient = test_recipient();

        let result = validate_transfer_params(&sender, &recipient, 0.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Amount must be positive"));
    }

    #[test]
    fn test_validate_transfer_params_too_small_amount() {
        let sender = test_sender();
        let recipient = test_recipient();
        let tiny_amount = 0.0000000001; 

        let result = validate_transfer_params(&sender, &recipient, tiny_amount);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Amount too small"));
    }

    #[test]
    fn test_validate_transfer_params_minimum_valid_amount() {
        let sender = test_sender();
        let recipient = test_recipient();
        let min_amount = 0.000000001; 

        let result = validate_transfer_params(&sender, &recipient, min_amount);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_validate_transfer_params_max_amount_too_large() {
        let sender = test_sender();
        let recipient = test_recipient();
        let huge_amount = 1e20; 

        let result = validate_transfer_params(&sender, &recipient, huge_amount);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Amount too large"));
    }

    #[test]
    fn test_validate_transfer_params_typical_amounts() {
        let sender = test_sender();
        let recipient = test_recipient();

        let test_cases = vec![
            (0.1, 100_000_000),
            (0.5, 500_000_000),
            (1.0, 1_000_000_000),
            (10.0, 10_000_000_000),
            (100.0, 100_000_000_000),
        ];

        for (amount_sol, expected_lamports) in test_cases {
            let result = validate_transfer_params(&sender, &recipient, amount_sol);
            assert!(result.is_ok(), "Failed for amount {}", amount_sol);
            assert_eq!(result.unwrap(), expected_lamports, "Wrong conversion for {}", amount_sol);
        }
    }

    #[test]
    fn test_validate_balance_sufficient() {
        let balance = 2_000_000_000; 
        let transfer = 1_000_000_000; 
        let fee = 5_000; 

        let result = validate_balance(balance, transfer, fee);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_balance_exact_sufficient() {
        let balance = 1_000_005_000; 
        let transfer = 1_000_000_000; 
        let fee = 5_000; 

        let result = validate_balance(balance, transfer, fee);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_balance_insufficient() {
        let balance = 500_000_000; 
        let transfer = 1_000_000_000; 
        let fee = 5_000; 

        let result = validate_balance(balance, transfer, fee);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Insufficient balance"));
    }

    #[test]
    fn test_validate_balance_insufficient_with_large_fee() {
        let balance = 1_000_010_000; 
        let transfer = 1_000_000_000; 
        let fee = 20_000; 

        let result = validate_balance(balance, transfer, fee);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Insufficient balance"));
    }

    #[test]
    fn test_validate_balance_zero_balance() {
        let balance = 0;
        let transfer = 1_000_000;
        let fee = 5_000;

        let result = validate_balance(balance, transfer, fee);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_balance_saturating_add_prevents_overflow() {
        let balance = u64::MAX;
        let transfer = u64::MAX / 2;
        let fee = u64::MAX / 2;
        let result = validate_balance(balance, transfer, fee);
        assert!(result.is_ok(), "Should handle overflow gracefully without panicking");
    }

}

