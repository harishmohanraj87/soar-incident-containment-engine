"""
Wazuh Webhook

Receives alerts from Wazuh Manager and forwards
them into the SOAR processing pipeline.
"""

from fastapi import APIRouter

from wazuh.parser import parse_wazuh_alert
from wazuh.mapper import map_to_soar

router = APIRouter(
    prefix="/wazuh",
    tags=["Wazuh Integration"]
)


@router.post("/webhook")
async def receive_wazuh_alert(alert: dict):
    """
    Receive alerts from Wazuh.
    """

    # -------------------------
    # Parse Wazuh Alert
    # -------------------------

    parsed_alert = parse_wazuh_alert(alert)

    # -------------------------
    # Convert to SOAR Format
    # -------------------------

    soar_alert = map_to_soar(parsed_alert)

    # -------------------------
    # TODO
    # Send into existing SOAR Pipeline
    # -------------------------

    return {

        "message": "Wazuh alert received",

        "parsed_alert": parsed_alert.model_dump(),

        "soar_alert": soar_alert

    }