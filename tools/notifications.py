"""
Notification System - Emails owner when approval is needed
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

OWNER_EMAIL = os.getenv("NOTIFICATION_EMAIL", "abhinav100.sharma@gmail.com")


class NotificationManager:
    """Sends notifications to the owner when decisions are needed"""

    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_pass = os.getenv("SMTP_PASS")
        self.from_email = os.getenv("FROM_EMAIL", self.smtp_user)
        self.owner_email = OWNER_EMAIL

    def is_configured(self) -> bool:
        return self.smtp_user is not None and self.smtp_pass is not None

    def send_email(self, subject: str, body: str, html: bool = False) -> bool:
        """Send email to owner"""
        if not self.is_configured():
            print(f"[EMAIL NOT SENT - SMTP not configured] {subject}")
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = self.owner_email

            if html:
                msg.attach(MIMEText(body, "html"))
            else:
                msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.starttls()
            server.login(self.smtp_user, self.smtp_pass)
            server.sendmail(self.from_email, self.owner_email, msg.as_string())
            server.quit()

            print(f"[EMAIL SENT] {subject}")
            return True

        except Exception as e:
            print(f"[EMAIL FAILED] {subject}: {e}")
            return False

    def notify_payment_required(
        self,
        service: str,
        amount: float,
        reason: str,
        action_url: str = None
    ):
        """Notify owner that a payment decision is needed"""
        subject = f"[APPROVAL NEEDED] Payment: ${amount} for {service}"

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #ff9800; color: white; padding: 20px; text-align: center;">
                <h1>Payment Approval Required</h1>
            </div>

            <div style="padding: 20px;">
                <table style="width: 100%;">
                    <tr>
                        <td><strong>Service:</strong></td>
                        <td>{service}</td>
                    </tr>
                    <tr>
                        <td><strong>Amount:</strong></td>
                        <td style="font-size: 24px; color: #ff9800;">${amount:.2f}</td>
                    </tr>
                    <tr>
                        <td><strong>Reason:</strong></td>
                        <td>{reason}</td>
                    </tr>
                    <tr>
                        <td><strong>Time:</strong></td>
                        <td>{datetime.now().strftime('%Y-%m-%d %H:%M')}</td>
                    </tr>
                </table>
            </div>

            <div style="padding: 20px; text-align: center;">
                <p>The swarm is paused waiting for your approval.</p>
                {f'<a href="{action_url}" style="background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">Approve Payment</a>' if action_url else ''}
            </div>

            <div style="padding: 20px; background: #f5f5f5; font-size: 12px;">
                <p>Reply APPROVE to this email or visit the dashboard to continue.</p>
            </div>
        </body>
        </html>
        """

        return self.send_email(subject, body, html=True)

    def notify_daily_report(self, metrics: dict):
        """Send daily status report"""
        subject = f"[Daily Report] OpenClaw Swarm - {datetime.now().strftime('%Y-%m-%d')}"

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #2196F3; color: white; padding: 20px; text-align: center;">
                <h1>Daily Swarm Report</h1>
                <p>{datetime.now().strftime('%Y-%m-%d')}</p>
            </div>

            <div style="padding: 20px;">
                <h2>Outreach Stats</h2>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px;"><strong>Messages Sent</strong></td>
                        <td style="padding: 10px;">{metrics.get('outreach', {}).get('total_sent', 0)}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px;"><strong>Responses</strong></td>
                        <td style="padding: 10px;">{metrics.get('outreach', {}).get('responses', 0)}</td>
                    </tr>
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px;"><strong>Response Rate</strong></td>
                        <td style="padding: 10px;">{metrics.get('outreach', {}).get('response_rate', 0)*100:.1f}%</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px;"><strong>Conversions</strong></td>
                        <td style="padding: 10px;">{metrics.get('outreach', {}).get('conversions', 0)}</td>
                    </tr>
                </table>

                <h2>Mission Progress</h2>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px;"><strong>Goal</strong></td>
                        <td style="padding: 10px;">{metrics.get('mission', {}).get('goal', '$1M MRR')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px;"><strong>Current MRR</strong></td>
                        <td style="padding: 10px;">${metrics.get('mission', {}).get('current_mrr', 0):,}</td>
                    </tr>
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px;"><strong>Customers</strong></td>
                        <td style="padding: 10px;">{metrics.get('mission', {}).get('customers', 0)}</td>
                    </tr>
                </table>

                <h2>Active Agents</h2>
                <p>{metrics.get('active_agents', 0)} agents running</p>
            </div>

            <div style="padding: 20px; background: #f5f5f5; text-align: center; font-size: 12px;">
                <p>OpenClaw Autonomous Swarm</p>
            </div>
        </body>
        </html>
        """

        return self.send_email(subject, body, html=True)

    def notify_improvement_proposed(self, improvement: dict):
        """Notify about proposed product improvement"""
        subject = f"[Product] Improvement Proposed: {improvement.get('title', 'Unknown')}"

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #9C27B0; color: white; padding: 20px; text-align: center;">
                <h1>Improvement Proposed</h1>
            </div>

            <div style="padding: 20px;">
                <h2>{improvement.get('title', 'Unknown')}</h2>
                <p>{improvement.get('description', 'No description')}</p>

                <table style="width: 100%; margin-top: 20px;">
                    <tr>
                        <td><strong>Impact Score:</strong></td>
                        <td>{improvement.get('impact_score', 0)}/10</td>
                    </tr>
                    <tr>
                        <td><strong>Effort Score:</strong></td>
                        <td>{improvement.get('effort_score', 0)}/10</td>
                    </tr>
                    <tr>
                        <td><strong>Priority:</strong></td>
                        <td>{improvement.get('priority_score', 0):.1f}</td>
                    </tr>
                </table>

                <div style="margin-top: 20px; padding: 10px; background: #f5f5f5;">
                    <strong>Triggered by feedback:</strong>
                    <p>{', '.join(improvement.get('triggered_by', []))}</p>
                </div>
            </div>
        </body>
        </html>
        """

        return self.send_email(subject, body, html=True)

    def notify_error(self, error_type: str, details: str):
        """Notify about critical errors"""
        subject = f"[ERROR] OpenClaw: {error_type}"

        body = f"""
        ERROR in OpenClaw Swarm

        Type: {error_type}
        Time: {datetime.now().isoformat()}

        Details:
        {details}

        The swarm may need attention.
        """

        return self.send_email(subject, body, html=False)


# Global instance
notifications = NotificationManager()


def notify_payment(service: str, amount: float, reason: str):
    """Convenience function for payment notifications"""
    return notifications.notify_payment_required(service, amount, reason)


def notify_daily(metrics: dict):
    """Convenience function for daily reports"""
    return notifications.notify_daily_report(metrics)
