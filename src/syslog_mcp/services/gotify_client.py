"""
Gotify client for sending alert notifications.
"""

import os
from typing import Optional
import aiohttp
from ..utils.logging import get_logger

logger = get_logger(__name__)


class GotifyClient:
    """Async client for sending notifications to Gotify server."""
    
    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None
    ):
        """Initialize Gotify client with URL and app token."""
        self.url = url or os.getenv("GOTIFY_URL", "")
        self.token = token or os.getenv("GOTIFY_TOKEN", "")
        self._session: Optional[aiohttp.ClientSession] = None
        
        if not self.url or not self.token:
            logger.warning("Gotify URL or token not configured - alerts will be logged only")
    
    async def __aenter__(self):
        """Async context manager entry."""
        if self.url and self.token:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._session:
            await self._session.close()
    
    def is_configured(self) -> bool:
        """Check if Gotify is properly configured."""
        return bool(self.url and self.token)
    
    async def send_notification(
        self,
        title: str,
        message: str,
        priority: int = 5
    ) -> bool:
        """
        Send notification to Gotify server.
        
        Args:
            title: Notification title
            message: Notification message content
            priority: Priority level (0-10, default 5)
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.is_configured():
            logger.warning(
                f"Gotify not configured - Alert would be sent: {title}",
                extra={"title": title, "message": message, "priority": priority}
            )
            return False
        
        if not self._session:
            logger.error("Gotify client session not initialized")
            return False
        
        try:
            # Prepare notification payload
            payload = {
                "title": title,
                "message": message,
                "priority": priority
            }
            
            # Send POST request to Gotify API
            url = f"{self.url.rstrip('/')}/message"
            headers = {"X-Gotify-Key": self.token}
            
            logger.debug(f"Sending Gotify notification to {url}")
            
            async with self._session.post(
                url,
                json=payload,
                headers=headers
            ) as response:
                if response.status == 200:
                    logger.info(
                        "Gotify notification sent successfully",
                        extra={"title": title, "priority": priority, "status": response.status}
                    )
                    return True
                else:
                    error_text = await response.text()
                    logger.error(
                        f"Failed to send Gotify notification: {response.status}",
                        extra={"status": response.status, "error": error_text}
                    )
                    return False
                    
        except aiohttp.ClientError as e:
            logger.error(f"Gotify client error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending Gotify notification: {e}")
            return False
    
    async def test_connection(self) -> bool:
        """
        Test connection to Gotify server.
        
        Returns:
            True if connection successful, False otherwise
        """
        if not self.is_configured():
            logger.warning("Gotify not configured - cannot test connection")
            return False
        
        if not self._session:
            logger.error("Gotify client session not initialized")
            return False
        
        try:
            # Test with a simple GET to /health or /version endpoint
            url = f"{self.url.rstrip('/')}/health"
            
            async with self._session.get(url) as response:
                if response.status == 200:
                    logger.info("Gotify server connection test successful")
                    return True
                else:
                    logger.error(f"Gotify server returned status: {response.status}")
                    return False
                    
        except aiohttp.ClientError as e:
            logger.error(f"Gotify connection test failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error testing Gotify connection: {e}")
            return False


async def send_alert_notification(
    title: str,
    message: str,
    priority: int = 5
) -> bool:
    """
    Convenience function to send a notification via Gotify.
    
    Args:
        title: Alert title
        message: Alert message
        priority: Priority level (0-10)
        
    Returns:
        True if sent successfully, False otherwise
    """
    async with GotifyClient() as client:
        return await client.send_notification(title, message, priority)


async def test_gotify_configuration() -> bool:
    """
    Test Gotify configuration and connectivity.
    
    Returns:
        True if configured and reachable, False otherwise
    """
    async with GotifyClient() as client:
        if not client.is_configured():
            return False
        return await client.test_connection()