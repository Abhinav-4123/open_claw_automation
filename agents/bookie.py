"""
THE BOOKIE - Venture Portfolio Manager
Manages multiple parallel business "bets" and allocates resources
"""
import os
import json
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


class BetStatus(Enum):
    QUEUED = "queued"
    ACTIVE = "active"
    WINNING = "winning"
    LOSING = "losing"
    CASHED_OUT = "cashed_out"
    BUSTED = "busted"


@dataclass
class Bet:
    """A business bet/venture"""
    id: str
    name: str
    category: str
    description: str
    status: BetStatus
    stake: float  # Capital invested
    current_value: float  # Current revenue
    potential_value: float  # Expected if successful
    odds: float  # Probability of success (0-1)
    started_at: datetime
    deadline: Optional[datetime] = None
    metrics: Dict = field(default_factory=dict)
    actions_taken: List[str] = field(default_factory=list)


class BookieAgent:
    """
    The Bookie - Venture Portfolio Manager

    Responsibilities:
    - Select which strategies to bet on
    - Allocate capital across bets
    - Monitor bet performance
    - Double down on winners
    - Cut losses on losers
    - Maintain portfolio balance
    """

    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.agent_id = f"bookie_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Portfolio
        self.bets: Dict[str, Bet] = {}
        self.total_bankroll = 10000  # Starting capital
        self.allocated_capital = 0
        self.available_capital = self.total_bankroll

        # Settings
        self.max_concurrent_bets = 10
        self.max_single_bet = 0.25  # Max 25% on single bet
        self.min_bet_size = 100

        # Performance
        self.total_winnings = 0
        self.total_losses = 0
        self.win_rate = 0

    async def evaluate_strategy(self, strategy: Dict) -> Dict:
        """Evaluate a strategy for betting potential"""

        prompt = f"""Evaluate this business strategy as a betting opportunity:

Strategy: {json.dumps(strategy, indent=2)}

Provide:
1. Success probability (0-1)
2. Expected ROI if successful
3. Time to know if it's working (days)
4. Key risks
5. Go/No-Go recommendation

Return JSON:
{{
    "success_probability": 0.7,
    "expected_roi": 3.5,
    "validation_days": 14,
    "risks": ["risk1", "risk2"],
    "recommendation": "go|no-go|maybe",
    "reasoning": "Why"
}}"""

        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except:
            return {
                "success_probability": 0.5,
                "expected_roi": 2.0,
                "validation_days": 30,
                "risks": ["Market uncertainty"],
                "recommendation": "maybe",
                "reasoning": "Insufficient data"
            }

    async def place_bet(self, strategy: Dict, stake: float) -> Optional[Bet]:
        """Place a new bet on a strategy"""

        # Validate stake
        if stake > self.available_capital:
            return None

        if stake > self.total_bankroll * self.max_single_bet:
            stake = self.total_bankroll * self.max_single_bet

        if stake < self.min_bet_size:
            return None

        # Check concurrent bet limit
        active_bets = len([b for b in self.bets.values() if b.status == BetStatus.ACTIVE])
        if active_bets >= self.max_concurrent_bets:
            return None

        # Evaluate the strategy
        evaluation = await self.evaluate_strategy(strategy)

        if evaluation.get("recommendation") == "no-go":
            return None

        # Create bet
        bet = Bet(
            id=f"bet_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            name=strategy.get("title", "Unknown Bet"),
            category=strategy.get("category", "general"),
            description=strategy.get("description", ""),
            status=BetStatus.ACTIVE,
            stake=stake,
            current_value=0,
            potential_value=stake * evaluation.get("expected_roi", 2),
            odds=evaluation.get("success_probability", 0.5),
            started_at=datetime.now(),
            deadline=datetime.now() + timedelta(days=evaluation.get("validation_days", 30)),
            metrics={
                "expected_roi": evaluation.get("expected_roi", 2),
                "risks": evaluation.get("risks", [])
            }
        )

        self.bets[bet.id] = bet
        self.allocated_capital += stake
        self.available_capital -= stake

        return bet

    def update_bet_value(self, bet_id: str, new_value: float):
        """Update the current value of a bet"""
        bet = self.bets.get(bet_id)
        if not bet:
            return

        bet.current_value = new_value

        # Update status based on performance
        roi = (new_value - bet.stake) / bet.stake if bet.stake > 0 else 0

        if roi > 0.5:  # 50%+ ROI
            bet.status = BetStatus.WINNING
        elif roi < -0.3:  # 30%+ loss
            bet.status = BetStatus.LOSING

    async def double_down(self, bet_id: str) -> bool:
        """Double the stake on a winning bet"""
        bet = self.bets.get(bet_id)
        if not bet or bet.status != BetStatus.WINNING:
            return False

        additional_stake = min(bet.stake, self.available_capital)
        if additional_stake < self.min_bet_size:
            return False

        bet.stake += additional_stake
        bet.potential_value *= 2
        self.allocated_capital += additional_stake
        self.available_capital -= additional_stake

        bet.actions_taken.append(f"Doubled down: +${additional_stake:,.0f}")

        return True

    async def cut_losses(self, bet_id: str) -> float:
        """Cut losses on a losing bet"""
        bet = self.bets.get(bet_id)
        if not bet:
            return 0

        # Calculate loss
        loss = bet.stake - bet.current_value
        recovery = bet.current_value

        # Update totals
        self.total_losses += loss
        self.available_capital += recovery
        self.allocated_capital -= bet.stake

        bet.status = BetStatus.BUSTED
        bet.actions_taken.append(f"Cut losses: recovered ${recovery:,.0f}")

        return recovery

    async def cash_out(self, bet_id: str) -> float:
        """Cash out a winning bet"""
        bet = self.bets.get(bet_id)
        if not bet:
            return 0

        profit = bet.current_value - bet.stake

        # Update totals
        self.total_winnings += profit
        self.available_capital += bet.current_value
        self.allocated_capital -= bet.stake

        bet.status = BetStatus.CASHED_OUT
        bet.actions_taken.append(f"Cashed out: profit ${profit:,.0f}")

        self._update_win_rate()

        return bet.current_value

    def _update_win_rate(self):
        """Update win rate statistics"""
        total_closed = len([b for b in self.bets.values()
                          if b.status in [BetStatus.CASHED_OUT, BetStatus.BUSTED]])
        if total_closed > 0:
            wins = len([b for b in self.bets.values() if b.status == BetStatus.CASHED_OUT])
            self.win_rate = wins / total_closed

    async def optimize_portfolio(self) -> Dict:
        """Optimize the current portfolio of bets"""

        decisions = {
            "double_down": [],
            "cut_losses": [],
            "hold": [],
            "cash_out": []
        }

        for bet_id, bet in self.bets.items():
            if bet.status == BetStatus.CASHED_OUT or bet.status == BetStatus.BUSTED:
                continue

            roi = (bet.current_value - bet.stake) / bet.stake if bet.stake > 0 else 0
            days_active = (datetime.now() - bet.started_at).days

            # Decision logic
            if roi > 1.0:  # 100%+ ROI - consider cashing out
                decisions["cash_out"].append(bet_id)
            elif roi > 0.3 and bet.status == BetStatus.WINNING:
                # Winning bet - double down
                if self.available_capital > bet.stake:
                    decisions["double_down"].append(bet_id)
                else:
                    decisions["hold"].append(bet_id)
            elif roi < -0.4 or (days_active > 30 and roi < 0):
                # Losing bet - cut losses
                decisions["cut_losses"].append(bet_id)
            else:
                decisions["hold"].append(bet_id)

        return decisions

    async def auto_manage(self):
        """Automatically manage portfolio based on optimization"""
        decisions = await self.optimize_portfolio()

        results = {"actions": []}

        for bet_id in decisions["double_down"][:2]:  # Max 2 double downs
            if await self.double_down(bet_id):
                results["actions"].append(f"Doubled down on {self.bets[bet_id].name}")

        for bet_id in decisions["cut_losses"]:
            recovery = await self.cut_losses(bet_id)
            results["actions"].append(f"Cut losses on {self.bets[bet_id].name}: recovered ${recovery:,.0f}")

        for bet_id in decisions["cash_out"]:
            total = await self.cash_out(bet_id)
            results["actions"].append(f"Cashed out {self.bets[bet_id].name}: ${total:,.0f}")

        return results

    def get_portfolio_summary(self) -> Dict:
        """Get portfolio summary for dashboard"""
        active_bets = [b for b in self.bets.values() if b.status == BetStatus.ACTIVE]
        winning_bets = [b for b in self.bets.values() if b.status == BetStatus.WINNING]

        total_current_value = sum(b.current_value for b in self.bets.values()
                                 if b.status not in [BetStatus.BUSTED, BetStatus.CASHED_OUT])

        return {
            "total_bankroll": self.total_bankroll + self.total_winnings - self.total_losses,
            "available_capital": self.available_capital,
            "allocated_capital": self.allocated_capital,
            "active_bets": len(active_bets),
            "winning_bets": len(winning_bets),
            "total_current_value": total_current_value,
            "total_winnings": self.total_winnings,
            "total_losses": self.total_losses,
            "win_rate": self.win_rate,
            "net_profit": self.total_winnings - self.total_losses
        }

    def get_all_bets(self) -> List[Dict]:
        """Get all bets for dashboard"""
        return [
            {
                "id": b.id,
                "name": b.name,
                "category": b.category,
                "status": b.status.value,
                "stake": b.stake,
                "current_value": b.current_value,
                "potential_value": b.potential_value,
                "roi": (b.current_value - b.stake) / b.stake * 100 if b.stake > 0 else 0,
                "odds": b.odds,
                "started": b.started_at.isoformat(),
                "actions": b.actions_taken[-5:]  # Last 5 actions
            }
            for b in self.bets.values()
        ]

    def get_status(self) -> Dict:
        """Get Bookie status"""
        summary = self.get_portfolio_summary()
        return {
            "agent_id": self.agent_id,
            **summary,
            "max_concurrent_bets": self.max_concurrent_bets,
            "max_single_bet_percent": self.max_single_bet * 100
        }


# Global Bookie instance
bookie = BookieAgent()
