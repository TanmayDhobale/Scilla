pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_SOL as f64
}

pub fn sol_to_lamports(sol: f64) -> u64 {
    (sol * LAMPORTS_PER_SOL as f64) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lamports_to_sol() {
        assert_eq!(lamports_to_sol(0), 0.0);
        assert_eq!(lamports_to_sol(LAMPORTS_PER_SOL), 1.0);
        assert_eq!(lamports_to_sol(LAMPORTS_PER_SOL * 10), 10.0);
        assert_eq!(lamports_to_sol(LAMPORTS_PER_SOL / 2), 0.5);
        assert_eq!(lamports_to_sol(1), 0.000000001);
        assert_eq!(lamports_to_sol(5_000), 0.000005);
    }

    #[test]
    fn test_sol_to_lamports() {
        assert_eq!(sol_to_lamports(0.0), 0);
        assert_eq!(sol_to_lamports(1.0), LAMPORTS_PER_SOL);
        assert_eq!(sol_to_lamports(10.0), LAMPORTS_PER_SOL * 10);
        assert_eq!(sol_to_lamports(0.5), LAMPORTS_PER_SOL / 2);
        assert_eq!(sol_to_lamports(0.000005), 5_000);
    }

    #[test]
    fn test_round_trip_conversion() {
        // Test that conversions are consistent
        let test_cases = vec![
            0u64,
            1u64,
            5_000u64,
            LAMPORTS_PER_SOL / 2,
            LAMPORTS_PER_SOL,
            LAMPORTS_PER_SOL * 10,
        ];

        for lamports in test_cases {
            let sol = lamports_to_sol(lamports);
            let back_to_lamports = sol_to_lamports(sol);
            // Allow small floating point differences
            let diff = lamports.abs_diff(back_to_lamports);
            assert!(
                diff <= 1,
                "Round trip failed: {} lamports -> {} SOL -> {} lamports (diff: {})",
                lamports,
                sol,
                back_to_lamports,
                diff
            );
        }
    }

    #[test]
    fn test_fee_conversion() {
        let estimated_fee_lamports = 5_000u64;
        let estimated_fee_sol = lamports_to_sol(estimated_fee_lamports);
        assert_eq!(estimated_fee_sol, 0.000005);
        
        // Verify it converts back correctly
        assert_eq!(sol_to_lamports(estimated_fee_sol), estimated_fee_lamports);
    }
}
