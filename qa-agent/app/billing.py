"""
Stripe Billing Integration
Handles subscriptions, payments, and usage tracking
"""
import os
from datetime import datetime
from typing import Optional, Dict, List
from fastapi import APIRouter, HTTPException, Request, Header
from pydantic import BaseModel
import stripe

# Initialize Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

router = APIRouter(prefix="/billing", tags=["billing"])

# Pricing Plans
PLANS = {
    "starter": {
        "name": "Starter",
        "price_id": os.getenv("STRIPE_STARTER_PRICE_ID", "price_starter"),
        "price": 499,
        "flows": 3,
        "features": ["Daily smoke tests", "Email alerts", "7-day history"]
    },
    "growth": {
        "name": "Growth",
        "price_id": os.getenv("STRIPE_GROWTH_PRICE_ID", "price_growth"),
        "price": 1499,
        "flows": 10,
        "features": ["Hourly testing", "Slack + Email alerts", "30-day history", "Priority support"]
    },
    "enterprise": {
        "name": "Enterprise",
        "price_id": os.getenv("STRIPE_ENTERPRISE_PRICE_ID", "price_enterprise"),
        "price": 2500,
        "flows": -1,  # Unlimited
        "features": ["Unlimited flows", "Custom integrations", "Compliance reports", "SLA guarantee"]
    }
}

# In-memory customer store (use database in production)
customers = {}


class CreateCustomerRequest(BaseModel):
    email: str
    name: str
    company: Optional[str] = None


class CreateSubscriptionRequest(BaseModel):
    customer_id: str
    plan: str  # starter, growth, enterprise


class Customer(BaseModel):
    id: str
    email: str
    name: str
    company: Optional[str]
    stripe_customer_id: str
    subscription_id: Optional[str]
    plan: Optional[str]
    status: str  # active, trialing, canceled, past_due
    created_at: datetime


@router.get("/plans")
async def get_plans():
    """Get available pricing plans"""
    return {"plans": PLANS}


@router.post("/customers")
async def create_customer(request: CreateCustomerRequest):
    """Create a new customer in Stripe"""
    try:
        # Create Stripe customer
        stripe_customer = stripe.Customer.create(
            email=request.email,
            name=request.name,
            metadata={"company": request.company or ""}
        )

        customer = Customer(
            id=stripe_customer.id[:8],
            email=request.email,
            name=request.name,
            company=request.company,
            stripe_customer_id=stripe_customer.id,
            subscription_id=None,
            plan=None,
            status="created",
            created_at=datetime.now()
        )

        customers[customer.id] = customer
        return customer

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/subscriptions")
async def create_subscription(request: CreateSubscriptionRequest):
    """Create a subscription for a customer"""
    if request.plan not in PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    customer = customers.get(request.customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    try:
        # Create subscription with 7-day trial
        subscription = stripe.Subscription.create(
            customer=customer.stripe_customer_id,
            items=[{"price": PLANS[request.plan]["price_id"]}],
            trial_period_days=7,
            payment_behavior="default_incomplete",
            expand=["latest_invoice.payment_intent"]
        )

        customer.subscription_id = subscription.id
        customer.plan = request.plan
        customer.status = subscription.status

        return {
            "subscription_id": subscription.id,
            "status": subscription.status,
            "client_secret": subscription.latest_invoice.payment_intent.client_secret if subscription.latest_invoice.payment_intent else None,
            "trial_end": subscription.trial_end
        }

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/checkout-session")
async def create_checkout_session(plan: str, customer_email: str):
    """Create a Stripe Checkout session for easy payment"""
    if plan not in PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price": PLANS[plan]["price_id"],
                "quantity": 1
            }],
            mode="subscription",
            success_url=os.getenv("APP_URL", "https://app.testguard.ai") + "/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=os.getenv("APP_URL", "https://app.testguard.ai") + "/pricing",
            customer_email=customer_email,
            subscription_data={
                "trial_period_days": 7
            }
        )

        return {"checkout_url": session.url, "session_id": session.id}

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    """Handle Stripe webhooks"""
    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle events
    if event.type == "customer.subscription.created":
        subscription = event.data.object
        await handle_subscription_created(subscription)

    elif event.type == "customer.subscription.updated":
        subscription = event.data.object
        await handle_subscription_updated(subscription)

    elif event.type == "customer.subscription.deleted":
        subscription = event.data.object
        await handle_subscription_deleted(subscription)

    elif event.type == "invoice.paid":
        invoice = event.data.object
        await handle_invoice_paid(invoice)

    elif event.type == "invoice.payment_failed":
        invoice = event.data.object
        await handle_payment_failed(invoice)

    return {"status": "success"}


async def handle_subscription_created(subscription):
    """Handle new subscription"""
    print(f"New subscription: {subscription.id}")
    # Update customer status, send welcome email, etc.


async def handle_subscription_updated(subscription):
    """Handle subscription update (upgrade/downgrade)"""
    print(f"Subscription updated: {subscription.id} -> {subscription.status}")
    # Update customer plan, adjust limits, etc.


async def handle_subscription_deleted(subscription):
    """Handle subscription cancellation"""
    print(f"Subscription canceled: {subscription.id}")
    # Disable testing, send churn email, etc.


async def handle_invoice_paid(invoice):
    """Handle successful payment"""
    print(f"Invoice paid: {invoice.id}")
    # Update billing records, send receipt, etc.


async def handle_payment_failed(invoice):
    """Handle failed payment"""
    print(f"Payment failed: {invoice.id}")
    # Send dunning email, pause service, etc.


@router.get("/customers/{customer_id}")
async def get_customer(customer_id: str):
    """Get customer details"""
    customer = customers.get(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer


@router.post("/customers/{customer_id}/cancel")
async def cancel_subscription(customer_id: str):
    """Cancel a customer's subscription"""
    customer = customers.get(customer_id)
    if not customer or not customer.subscription_id:
        raise HTTPException(status_code=404, detail="Subscription not found")

    try:
        stripe.Subscription.delete(customer.subscription_id)
        customer.status = "canceled"
        return {"status": "canceled"}
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/usage/{customer_id}")
async def get_usage(customer_id: str):
    """Get customer's usage statistics"""
    # In production, pull from database
    return {
        "customer_id": customer_id,
        "period": "current",
        "tests_run": 45,
        "tests_limit": PLANS.get("growth", {}).get("flows", 10) * 30,
        "alerts_sent": 3,
        "uptime_percentage": 99.2
    }
