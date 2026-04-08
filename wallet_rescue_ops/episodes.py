"""Deterministic seeded episode catalog for Wallet Rescue Ops."""

from __future__ import annotations

from dataclasses import dataclass

from .models import IncidentLabel


@dataclass(frozen=True)
class AssetSpec:
    symbol: str
    amount: float
    usd_price: float

    @property
    def usd_value(self) -> float:
        return round(self.amount * self.usd_price, 2)


@dataclass(frozen=True)
class ApprovalSpec:
    approval_id: str
    spender: str
    asset: str
    allowance: float
    usd_exposure: float
    risk_hint: str
    created_from: str
    inspection_summary: str
    simulation_summary: str
    trigger_step: int | None
    is_malicious: bool


@dataclass(frozen=True)
class TransactionSpec:
    tx_id: str
    asset: str
    amount: float
    destination: str
    risk_hint: str
    preview: str
    inspection_summary: str
    simulation_summary: str
    trigger_step: int | None
    is_malicious: bool


@dataclass(frozen=True)
class WalletEpisodeSpec:
    episode_key: str
    family: str
    title: str
    user_context: str
    safe_vault_destination: str
    high_value_threshold_usd: float
    secondary_approval_required: bool
    max_steps: int
    already_lost_before_episode_usd: float
    expected_incident_label: IncidentLabel
    assets: tuple[AssetSpec, ...]
    approvals: tuple[ApprovalSpec, ...]
    pending_transactions: tuple[TransactionSpec, ...]
    reference_facts: tuple[str, ...]
    ideal_actions: tuple[str, ...]

    @property
    def recoverable_usd(self) -> float:
        return round(sum(asset.usd_value for asset in self.assets), 2)


def asset(symbol: str, amount: float, usd_price: float) -> AssetSpec:
    return AssetSpec(symbol=symbol, amount=amount, usd_price=usd_price)


def approval(
    approval_id: str,
    spender: str,
    asset_symbol: str,
    allowance: float,
    usd_exposure: float,
    risk_hint: str,
    created_from: str,
    inspection_summary: str,
    simulation_summary: str,
    trigger_step: int | None,
    *,
    is_malicious: bool,
) -> ApprovalSpec:
    return ApprovalSpec(
        approval_id=approval_id,
        spender=spender,
        asset=asset_symbol,
        allowance=allowance,
        usd_exposure=usd_exposure,
        risk_hint=risk_hint,
        created_from=created_from,
        inspection_summary=inspection_summary,
        simulation_summary=simulation_summary,
        trigger_step=trigger_step,
        is_malicious=is_malicious,
    )


def pending_tx(
    tx_id: str,
    asset_symbol: str,
    amount: float,
    destination: str,
    risk_hint: str,
    preview: str,
    inspection_summary: str,
    simulation_summary: str,
    trigger_step: int | None,
    *,
    is_malicious: bool,
) -> TransactionSpec:
    return TransactionSpec(
        tx_id=tx_id,
        asset=asset_symbol,
        amount=amount,
        destination=destination,
        risk_hint=risk_hint,
        preview=preview,
        inspection_summary=inspection_summary,
        simulation_summary=simulation_summary,
        trigger_step=trigger_step,
        is_malicious=is_malicious,
    )


EPISODE_CATALOG: tuple[WalletEpisodeSpec, ...] = (
    WalletEpisodeSpec(
        episode_key="airdrop-mirage",
        family="fake_airdrop",
        title="Airdrop Mirage",
        user_context=(
            "You clicked a fake airdrop claim link. The wallet now shows a fresh "
            "USDC approval and the user is panicking because funds have not moved yet."
        ),
        safe_vault_destination="vault://cold-alpha",
        high_value_threshold_usd=1000.0,
        secondary_approval_required=True,
        max_steps=7,
        already_lost_before_episode_usd=0.0,
        expected_incident_label=IncidentLabel.FAKE_AIRDROP_APPROVAL_ATTACK,
        assets=(asset("USDC", 1200.0, 1.0), asset("SOL", 3.0, 145.0)),
        approvals=(
            approval(
                "apr-air-001",
                "Nebula Airdrop Router",
                "USDC",
                1200.0,
                1200.0,
                "New approval appeared right after a fake airdrop click.",
                "wallet popup after reward claim",
                "Nebula Airdrop Router is not allowlisted and the approval matches the full USDC balance.",
                "Simulation shows Nebula Airdrop Router can pull the full 1200 USDC in one call.",
                3,
                is_malicious=True,
            ),
            approval(
                "apr-air-002",
                "Jupiter DCA",
                "SOL",
                0.25,
                36.25,
                "Looks risky because it was refreshed today, but it matches a known allowlisted protocol.",
                "previous automated DCA setup",
                "Jupiter DCA is allowlisted and only has a small recurring SOL allowance.",
                "Simulation shows the approval only powers a tiny recurring swap owned by the user.",
                None,
                is_malicious=False,
            ),
        ),
        pending_transactions=(),
        reference_facts=(
            "Nebula Airdrop Router approval was malicious.",
            "Jupiter DCA approval was benign.",
            "The safest vault was vault://cold-alpha.",
        ),
        ideal_actions=(
            "scan_wallet",
            "inspect_transaction:apr-air-001",
            "revoke_approval:apr-air-001",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="nft-mint-gas-trap",
        family="fake_airdrop",
        title="NFT Mint Gas Trap",
        user_context=(
            "The user signed an NFT mint helper prompt. BONK and USDC balances are still present, "
            "but a suspicious spender called MintGas Relay was added minutes ago."
        ),
        safe_vault_destination="vault://cold-alpha",
        high_value_threshold_usd=1000.0,
        secondary_approval_required=True,
        max_steps=7,
        already_lost_before_episode_usd=0.0,
        expected_incident_label=IncidentLabel.FAKE_AIRDROP_APPROVAL_ATTACK,
        assets=(
            asset("USDC", 980.0, 1.0),
            asset("BONK", 1800000.0, 0.000018),
            asset("SOL", 5.0, 145.0),
        ),
        approvals=(
            approval(
                "apr-air-101",
                "MintGas Relay",
                "USDC",
                980.0,
                980.0,
                "New relay approval references a mint helper contract with no prior history.",
                "gasless mint signature",
                "MintGas Relay is not allowlisted and the approval can consume the entire USDC float.",
                "Simulation shows MintGas Relay can use permit-style transfer to empty the USDC balance.",
                4,
                is_malicious=True,
            ),
            approval(
                "apr-air-102",
                "Marinade Staking",
                "SOL",
                0.5,
                72.5,
                "This approval refreshed recently because the user restaked.",
                "existing staking workflow",
                "Marinade Staking is allowlisted and matches the user's staking history.",
                "Simulation shows this approval only touches a small staking maintenance amount.",
                None,
                is_malicious=False,
            ),
        ),
        pending_transactions=(),
        reference_facts=(
            "MintGas Relay approval was malicious.",
            "Marinade Staking approval was benign.",
            "The user needed vault://cold-alpha for containment.",
        ),
        ideal_actions=(
            "scan_wallet",
            "simulate_transaction:apr-air-101",
            "revoke_approval:apr-air-101",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="stablecoin-reward-center",
        family="fake_airdrop",
        title="Stablecoin Reward Center",
        user_context=(
            "A fake stablecoin rewards portal asked for a signature. No transfer has fired yet, "
            "but both USDC and PYUSD are still sitting in the compromised hot wallet."
        ),
        safe_vault_destination="vault://cold-bravo",
        high_value_threshold_usd=1500.0,
        secondary_approval_required=True,
        max_steps=8,
        already_lost_before_episode_usd=0.0,
        expected_incident_label=IncidentLabel.FAKE_AIRDROP_APPROVAL_ATTACK,
        assets=(
            asset("USDC", 3200.0, 1.0),
            asset("PYUSD", 500.0, 1.0),
            asset("SOL", 2.0, 145.0),
        ),
        approvals=(
            approval(
                "apr-air-201",
                "Reward Center Permit",
                "USDC",
                3200.0,
                3200.0,
                "Fresh permit targets the entire stablecoin balance.",
                "reward portal permit flow",
                "Reward Center Permit is not allowlisted and the approval has full-wallet scope.",
                "Simulation shows the permit can drain all 3200 USDC immediately after a matching call.",
                3,
                is_malicious=True,
            ),
            approval(
                "apr-air-202",
                "Kamino Lend",
                "PYUSD",
                50.0,
                50.0,
                "Small protocol approval appears noisy but matches prior lending behavior.",
                "existing lending position",
                "Kamino Lend is allowlisted and only covers a small maintenance allowance.",
                "Simulation shows the approval only services a tiny rebalance for the user's own position.",
                None,
                is_malicious=False,
            ),
        ),
        pending_transactions=(),
        reference_facts=(
            "Reward Center Permit approval was malicious.",
            "Kamino Lend approval was benign.",
            "High-value transfers required secondary approval for vault://cold-bravo.",
        ),
        ideal_actions=(
            "scan_wallet",
            "inspect_transaction:apr-air-201",
            "revoke_approval:apr-air-201",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="queued-sweep-to-burner",
        family="pending_drainer",
        title="Queued Sweep to Burner",
        user_context=(
            "A drainer queued a USDC sweep transaction that looks like a vault sync. "
            "If you do nothing, the transaction will execute almost immediately."
        ),
        safe_vault_destination="vault://ops-hotline",
        high_value_threshold_usd=2500.0,
        secondary_approval_required=True,
        max_steps=6,
        already_lost_before_episode_usd=0.0,
        expected_incident_label=IncidentLabel.QUEUED_WALLET_DRAINER,
        assets=(asset("USDC", 5000.0, 1.0), asset("SOL", 6.0, 145.0)),
        approvals=(
            approval(
                "apr-pnd-001",
                "Sync Router V2",
                "USDC",
                5000.0,
                5000.0,
                "Approval shares branding with a fake vault sync assistant.",
                "spoofed recovery helper",
                "Sync Router V2 is not allowlisted and mirrors the queued drainer destination.",
                "Simulation shows Sync Router V2 can repeatedly drain the full USDC wallet balance.",
                4,
                is_malicious=True,
            ),
            approval(
                "apr-pnd-002",
                "Orca Whirlpool",
                "SOL",
                0.1,
                14.5,
                "Small SOL allowance to a known AMM looks scary but matches trading history.",
                "existing LP position",
                "Orca Whirlpool is allowlisted and has a tiny exposure.",
                "Simulation shows the approval only services a user-owned LP rebalance.",
                None,
                is_malicious=False,
            ),
        ),
        pending_transactions=(
            pending_tx(
                "tx-pnd-001",
                "USDC",
                5000.0,
                "Drainer Burner 0xA11",
                "Transaction preview looks like a vault sync but destination is not allowlisted.",
                "Approve sync -> transfer 5000 USDC to Drainer Burner 0xA11.",
                "Inspection shows the queued destination is a burner wallet with no relationship to the user's vault.",
                "Simulation shows the queued transfer moves all 5000 USDC out of the wallet at the next execution window.",
                2,
                is_malicious=True,
            ),
        ),
        reference_facts=(
            "The queued USDC sweep was malicious.",
            "Sync Router V2 approval was malicious.",
            "The only safe vault was vault://ops-hotline.",
        ),
        ideal_actions=(
            "scan_wallet",
            "simulate_transaction:tx-pnd-001",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "revoke_approval:apr-pnd-001",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="bridge-refund-decoy",
        family="pending_drainer",
        title="Bridge Refund Decoy",
        user_context=(
            "The user thinks a bridge refund is pending, but the queued transfer and a fresh approval "
            "both point to a spoofed bridge assistant."
        ),
        safe_vault_destination="vault://ops-hotline",
        high_value_threshold_usd=2000.0,
        secondary_approval_required=True,
        max_steps=7,
        already_lost_before_episode_usd=0.0,
        expected_incident_label=IncidentLabel.QUEUED_WALLET_DRAINER,
        assets=(
            asset("USDC", 2600.0, 1.0),
            asset("mSOL", 8.0, 160.0),
            asset("SOL", 4.0, 145.0),
        ),
        approvals=(
            approval(
                "apr-pnd-101",
                "BridgeAssist Refund",
                "USDC",
                2600.0,
                2600.0,
                "Branding resembles a real bridge but the spender is newly deployed.",
                "refund claim helper",
                "BridgeAssist Refund is not allowlisted and the spender was created the same hour as the incident.",
                "Simulation shows BridgeAssist Refund can empty the stablecoin wallet once the queued transfer lands.",
                4,
                is_malicious=True,
            ),
            approval(
                "apr-pnd-102",
                "JitoSOL Restake",
                "SOL",
                0.2,
                29.0,
                "Small maintenance approval to a known protocol.",
                "existing validator automation",
                "JitoSOL Restake is allowlisted and low risk.",
                "Simulation shows the approval only handles a tiny validator rebalance.",
                None,
                is_malicious=False,
            ),
        ),
        pending_transactions=(
            pending_tx(
                "tx-pnd-101",
                "USDC",
                2100.0,
                "BridgeAssist Refund Pool",
                "Preview claims the user will receive funds after the transfer settles.",
                "BridgeAssist refund pipeline moves 2100 USDC to BridgeAssist Refund Pool.",
                "Inspection shows the bridge pool is not connected to the user's historical bridge routes.",
                "Simulation shows 2100 USDC leaves the wallet permanently with no refund leg.",
                3,
                is_malicious=True,
            ),
        ),
        reference_facts=(
            "BridgeAssist Refund queue was malicious.",
            "BridgeAssist Refund approval was malicious.",
            "JitoSOL Restake approval was benign.",
        ),
        ideal_actions=(
            "scan_wallet",
            "inspect_transaction:tx-pnd-101",
            "simulate_transaction:tx-pnd-101",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="payroll-export-leak",
        family="pending_drainer",
        title="Payroll Export Leak",
        user_context=(
            "A fake payroll export assistant queued a large stablecoin transfer. "
            "The CFO says the destination 'looks familiar', but the entity is not allowlisted."
        ),
        safe_vault_destination="vault://corp-cold-1",
        high_value_threshold_usd=3000.0,
        secondary_approval_required=True,
        max_steps=7,
        already_lost_before_episode_usd=0.0,
        expected_incident_label=IncidentLabel.QUEUED_WALLET_DRAINER,
        assets=(asset("USDC", 7800.0, 1.0), asset("SOL", 12.0, 145.0)),
        approvals=(
            approval(
                "apr-pnd-201",
                "Payroll Export Agent",
                "USDC",
                7800.0,
                7800.0,
                "A full-balance approval appeared from a spoofed payroll export agent.",
                "fake support handoff",
                "Payroll Export Agent is not allowlisted and has full treasury exposure.",
                "Simulation shows the agent approval can repeatedly drain payroll funds if left active.",
                5,
                is_malicious=True,
            ),
        ),
        pending_transactions=(
            pending_tx(
                "tx-pnd-201",
                "USDC",
                6200.0,
                "Ops Backup 12",
                "Preview labels the destination as a backup wallet even though it is unknown.",
                "Payroll export sends 6200 USDC to Ops Backup 12.",
                "Inspection shows Ops Backup 12 is absent from the company's approved vault list.",
                "Simulation shows the queued transfer sends 6200 USDC to an attacker-controlled destination.",
                3,
                is_malicious=True,
            ),
        ),
        reference_facts=(
            "The queued payroll export was malicious.",
            "Payroll Export Agent approval was malicious.",
            "The correct vault was vault://corp-cold-1.",
        ),
        ideal_actions=(
            "scan_wallet",
            "simulate_transaction:tx-pnd-201",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "revoke_approval:apr-pnd-201",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="mixed-approval-maze",
        family="mixed_signal",
        title="Mixed Approval Maze",
        user_context=(
            "The wallet contains two new approvals with similar names. One belongs to a known DCA flow; "
            "the other is a spoof that can drain the entire stablecoin stack."
        ),
        safe_vault_destination="vault://cold-charlie",
        high_value_threshold_usd=1200.0,
        secondary_approval_required=True,
        max_steps=8,
        already_lost_before_episode_usd=0.0,
        expected_incident_label=IncidentLabel.MIXED_SIGNAL_COMPROMISE,
        assets=(
            asset("USDC", 1800.0, 1.0),
            asset("JUP", 500.0, 0.8),
            asset("SOL", 4.0, 145.0),
        ),
        approvals=(
            approval(
                "apr-mix-001",
                "Jup1ter Rewards",
                "USDC",
                1800.0,
                1800.0,
                "Looks close to Jupiter branding but the name is misspelled.",
                "fake reward center",
                "Jup1ter Rewards uses spoofed branding and requests full-wallet access.",
                "Simulation shows Jup1ter Rewards can pull the entire USDC balance immediately.",
                4,
                is_malicious=True,
            ),
            approval(
                "apr-mix-002",
                "Jupiter DCA",
                "SOL",
                0.15,
                21.75,
                "The naming is close to the malicious spender, but this one is allowlisted.",
                "existing DCA setup",
                "Jupiter DCA is the real allowlisted protocol with tiny exposure.",
                "Simulation shows this approval only powers a small recurring user-owned trade.",
                None,
                is_malicious=False,
            ),
        ),
        pending_transactions=(),
        reference_facts=(
            "Jup1ter Rewards was malicious.",
            "Jupiter DCA was benign.",
            "The user still needed the safe vault vault://cold-charlie.",
        ),
        ideal_actions=(
            "scan_wallet",
            "inspect_transaction:apr-mix-001",
            "simulate_transaction:apr-mix-001",
            "revoke_approval:apr-mix-001",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="staking-exit-panic",
        family="mixed_signal",
        title="Staking Exit Panic",
        user_context=(
            "A user sees a queued staking exit and assumes everything is malicious. "
            "One approval really is bad, but the staking exit itself is benign."
        ),
        safe_vault_destination="vault://cold-charlie",
        high_value_threshold_usd=1000.0,
        secondary_approval_required=True,
        max_steps=8,
        already_lost_before_episode_usd=0.0,
        expected_incident_label=IncidentLabel.MIXED_SIGNAL_COMPROMISE,
        assets=(
            asset("USDC", 1500.0, 1.0),
            asset("mSOL", 10.0, 160.0),
            asset("SOL", 3.0, 145.0),
        ),
        approvals=(
            approval(
                "apr-mix-101",
                "Validator Refund Helper",
                "USDC",
                1500.0,
                1500.0,
                "Spoofed refund helper asks for the full stablecoin float.",
                "fake support recovery flow",
                "Validator Refund Helper is not allowlisted and requests full-wallet access.",
                "Simulation shows Validator Refund Helper can drain all 1500 USDC.",
                4,
                is_malicious=True,
            ),
            approval(
                "apr-mix-102",
                "Meteora DLMM",
                "SOL",
                0.1,
                14.5,
                "Known protocol approval with tiny exposure, easy to overreact to under stress.",
                "existing LP automation",
                "Meteora DLMM is allowlisted and low exposure.",
                "Simulation shows the approval only services a small LP position.",
                None,
                is_malicious=False,
            ),
        ),
        pending_transactions=(
            pending_tx(
                "tx-mix-101",
                "mSOL",
                1.0,
                "Stake Exit Program",
                "Queued exit looks scary, but the destination is an allowlisted program-owned escrow.",
                "Staking exit moves 1.0 mSOL to Stake Exit Program escrow.",
                "Inspection shows the staking exit routes to a known program escrow tied to the user's validator account.",
                "Simulation shows the user receives SOL back after the epoch closes; no attacker destination is involved.",
                None,
                is_malicious=False,
            ),
        ),
        reference_facts=(
            "Validator Refund Helper was malicious.",
            "The staking exit transaction was benign.",
            "Meteora DLMM approval was benign.",
        ),
        ideal_actions=(
            "scan_wallet",
            "simulate_transaction:tx-mix-101",
            "revoke_approval:apr-mix-101",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="market-maker-or-drainer",
        family="mixed_signal",
        title="Market Maker or Drainer",
        user_context=(
            "Two approvals and one queued transaction share near-identical names. "
            "A rushed agent can easily revoke the wrong thing or miss the real drainer."
        ),
        safe_vault_destination="vault://cold-delta",
        high_value_threshold_usd=1400.0,
        secondary_approval_required=True,
        max_steps=8,
        already_lost_before_episode_usd=0.0,
        expected_incident_label=IncidentLabel.MIXED_SIGNAL_COMPROMISE,
        assets=(asset("USDC", 2200.0, 1.0), asset("SOL", 5.0, 145.0)),
        approvals=(
            approval(
                "apr-mix-201",
                "Market-Makr Vault",
                "USDC",
                2200.0,
                2200.0,
                "Spender name is one character off from the allowlisted market-maker helper.",
                "spoofed liquidity helper",
                "Market-Makr Vault is a spoof and not allowlisted.",
                "Simulation shows Market-Makr Vault can drain all 2200 USDC.",
                4,
                is_malicious=True,
            ),
            approval(
                "apr-mix-202",
                "Market-Maker Vault",
                "SOL",
                0.05,
                7.25,
                "Real protocol name differs by one character from the spoof.",
                "existing MM strategy",
                "Market-Maker Vault is allowlisted and only has tiny SOL exposure.",
                "Simulation shows this approval only manages a small user-owned market-making strategy.",
                None,
                is_malicious=False,
            ),
        ),
        pending_transactions=(
            pending_tx(
                "tx-mix-201",
                "USDC",
                1100.0,
                "Market-Makr Exit",
                "Preview suggests a partial strategy exit but the destination is suspicious.",
                "Strategy exit sends 1100 USDC to Market-Makr Exit.",
                "Inspection shows the destination mirrors the spoofed spender, not the allowlisted market maker.",
                "Simulation shows 1100 USDC leaves the wallet to the attacker if not contained.",
                3,
                is_malicious=True,
            ),
        ),
        reference_facts=(
            "Market-Makr Vault approval was malicious.",
            "Market-Maker Vault approval was benign.",
            "Market-Makr Exit queued transaction was malicious.",
        ),
        ideal_actions=(
            "scan_wallet",
            "simulate_transaction:tx-mix-201",
            "revoke_approval:apr-mix-201",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="already-drained-once",
        family="post_compromise",
        title="Already Drained Once",
        user_context=(
            "A first drain already happened before the agent was called in. "
            "The remaining funds are still exposed through the same malicious approval."
        ),
        safe_vault_destination="vault://recovery-1",
        high_value_threshold_usd=1200.0,
        secondary_approval_required=True,
        max_steps=7,
        already_lost_before_episode_usd=1200.0,
        expected_incident_label=IncidentLabel.POST_COMPROMISE_SALVAGE,
        assets=(asset("USDC", 2400.0, 1.0), asset("SOL", 8.0, 145.0)),
        approvals=(
            approval(
                "apr-sal-001",
                "Reward Restore",
                "USDC",
                2400.0,
                2400.0,
                "The attacker already used this approval once and can use it again.",
                "fake recovery portal",
                "Reward Restore is malicious and still active after the first drain.",
                "Simulation shows the approval can drain the remaining 2400 USDC immediately.",
                3,
                is_malicious=True,
            ),
        ),
        pending_transactions=(),
        reference_facts=(
            "The wallet had already lost 1200 USD before the episode started.",
            "Reward Restore approval was malicious.",
            "The remaining funds needed to move to vault://recovery-1.",
        ),
        ideal_actions=(
            "scan_wallet",
            "revoke_approval:apr-sal-001",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="partial-sol-sweep",
        family="post_compromise",
        title="Partial SOL Sweep",
        user_context=(
            "A partial SOL sweep already executed, and the attacker left behind one more queued transfer. "
            "You have a narrow window to salvage the stablecoin balance."
        ),
        safe_vault_destination="vault://recovery-2",
        high_value_threshold_usd=1500.0,
        secondary_approval_required=True,
        max_steps=7,
        already_lost_before_episode_usd=870.0,
        expected_incident_label=IncidentLabel.POST_COMPROMISE_SALVAGE,
        assets=(asset("USDC", 3100.0, 1.0), asset("SOL", 2.0, 145.0)),
        approvals=(
            approval(
                "apr-sal-101",
                "Support Recovery Desk",
                "USDC",
                3100.0,
                3100.0,
                "Spoofed support desk still has full stablecoin access.",
                "fake support DM",
                "Support Recovery Desk is malicious and can drain all remaining stablecoins.",
                "Simulation shows the approval can drain the remaining 3100 USDC.",
                4,
                is_malicious=True,
            ),
        ),
        pending_transactions=(
            pending_tx(
                "tx-sal-101",
                "USDC",
                1800.0,
                "Recovery Desk Cold Wallet",
                "Queued transfer claims it will refund the user after support verification.",
                "Support verification transfer sends 1800 USDC to Recovery Desk Cold Wallet.",
                "Inspection shows Recovery Desk Cold Wallet is not in the approved vault list.",
                "Simulation shows 1800 USDC leaves the wallet permanently.",
                3,
                is_malicious=True,
            ),
        ),
        reference_facts=(
            "The wallet had already lost 870 USD before the episode started.",
            "Support Recovery Desk approval was malicious.",
            "The queued support verification transfer was malicious.",
        ),
        ideal_actions=(
            "scan_wallet",
            "simulate_transaction:tx-sal-101",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "revoke_approval:apr-sal-101",
            "finish_incident",
        ),
    ),
    WalletEpisodeSpec(
        episode_key="spoofed-support-aftercare",
        family="post_compromise",
        title="Spoofed Support Aftercare",
        user_context=(
            "Fake support told the user to wait while they 'secured' the wallet. "
            "One small benign approval remains, but the real danger is a queued USDC drain and an active spoofed helper."
        ),
        safe_vault_destination="vault://recovery-3",
        high_value_threshold_usd=1000.0,
        secondary_approval_required=True,
        max_steps=8,
        already_lost_before_episode_usd=600.0,
        expected_incident_label=IncidentLabel.POST_COMPROMISE_SALVAGE,
        assets=(
            asset("USDC", 1700.0, 1.0),
            asset("PYUSD", 400.0, 1.0),
            asset("SOL", 3.0, 145.0),
        ),
        approvals=(
            approval(
                "apr-sal-201",
                "Support Confirm Helper",
                "USDC",
                1700.0,
                1700.0,
                "Spoofed helper remains active from the fake support flow.",
                "fake support conversation",
                "Support Confirm Helper is malicious and still has full access to USDC.",
                "Simulation shows the helper can drain the remaining 1700 USDC.",
                5,
                is_malicious=True,
            ),
            approval(
                "apr-sal-202",
                "Kamino Lend",
                "PYUSD",
                25.0,
                25.0,
                "Tiny allowlisted approval remains from a prior lending position.",
                "existing lending position",
                "Kamino Lend is benign and low exposure.",
                "Simulation shows the approval only services a small maintenance action.",
                None,
                is_malicious=False,
            ),
        ),
        pending_transactions=(
            pending_tx(
                "tx-sal-201",
                "USDC",
                900.0,
                "Support Queue 44",
                "Queued transaction looks like a support lock, but the destination is unknown.",
                "Support queue sends 900 USDC to Support Queue 44.",
                "Inspection shows the destination is not an approved vault or escrow.",
                "Simulation shows 900 USDC will be drained at the next execution window.",
                3,
                is_malicious=True,
            ),
        ),
        reference_facts=(
            "The wallet had already lost 600 USD before the episode started.",
            "Support Confirm Helper approval was malicious.",
            "Support Queue 44 transaction was malicious.",
            "Kamino Lend approval was benign.",
        ),
        ideal_actions=(
            "scan_wallet",
            "simulate_transaction:tx-sal-201",
            "revoke_approval:apr-sal-201",
            "request_secondary_approval",
            "transfer_to_safe_vault:USDC",
            "finish_incident",
        ),
    ),
)


def get_episode(
    seed: int | None = None,
    *,
    scenario_id: str | None = None,
    cycle_index: int = 0,
) -> tuple[int, WalletEpisodeSpec]:
    """Pick an episode deterministically."""
    if scenario_id:
        for index, episode in enumerate(EPISODE_CATALOG):
            if episode.episode_key == scenario_id:
                chosen_seed = index if seed is None else seed
                return chosen_seed, episode
        raise ValueError(f"Unknown scenario_id: {scenario_id}")

    if seed is None:
        index = cycle_index % len(EPISODE_CATALOG)
        return index, EPISODE_CATALOG[index]

    index = seed % len(EPISODE_CATALOG)
    return seed, EPISODE_CATALOG[index]


def list_episode_ids() -> tuple[str, ...]:
    """Return the available scenario identifiers."""
    return tuple(episode.episode_key for episode in EPISODE_CATALOG)
