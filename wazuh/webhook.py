"""
Wazuh Webhook Integration

Receives alerts from Wazuh Manager, parses them,
maps them to the standard SOAR alert format,
and forwards them into the existing SOAR pipeline.
"""

import os
import secrets

from fastapi import APIRouter, HTTPException, Request

from wazuh.parser import parse_wazuh_alert
from wazuh.mapper import map_to_soar


router = APIRouter(
    prefix="/wazuh",
    tags=["Wazuh Integration"],
)


@router.post("/webhook")
async def receive_wazuh_alert(request: Request, alert: dict):
    """
    Receive a raw Wazuh alert and process it through
    the existing SOAR alert pipeline.
    """

    # The webhook is fail-closed: an unset secret disables ingestion rather
    # than exposing a public unauthenticated containment endpoint.
    configured_secret = os.getenv("WAZUH_WEBHOOK_SECRET")
    provided_secret = request.headers.get("X-Wazuh-Webhook-Secret", "")
    if not configured_secret:
        raise HTTPException(status_code=503, detail="Wazuh webhook authentication is not configured.")
    if not provided_secret or not secrets.compare_digest(provided_secret, configured_secret):
        raise HTTPException(status_code=401, detail="Invalid Wazuh webhook credentials.")

    # ------------------------------------------------------
    # VALIDATE REQUEST
    # ------------------------------------------------------

    if not isinstance(alert, dict):
        raise HTTPException(
            status_code=400,
            detail="Wazuh alert must be a JSON object",
        )

    # ------------------------------------------------------
    # PARSE WAZUH ALERT
    # ------------------------------------------------------

    try:
        parsed_alert = parse_wazuh_alert(alert)

    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid Wazuh alert: {error}",
        )

    except Exception as error:
        print(
            f"Wazuh parsing error: {error}"
        )

        raise HTTPException(
            status_code=400,
            detail="Unable to parse Wazuh alert",
        )

    # ------------------------------------------------------
    # MAP TO STANDARD SOAR FORMAT
    # ------------------------------------------------------

    try:
        soar_alert = map_to_soar(parsed_alert)

    except Exception as error:
        print(
            f"Wazuh mapping error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to map Wazuh alert to SOAR format",
        )

    # ------------------------------------------------------
    # CONNECT TO EXISTING SOAR PIPELINE
    # ------------------------------------------------------

    try:
        # Import here deliberately.
        #
        # This avoids a circular import because backend.main
        # already imports the Wazuh router.
        from backend.main import process_alert

        result = process_alert(
            soar_alert
        )

    except ValueError as error:
        print(
            f"Wazuh SOAR validation error: {error}"
        )

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:
        print(
            f"Wazuh SOAR processing error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to process Wazuh alert",
        )

    # ------------------------------------------------------
    # RESPONSE
    # ------------------------------------------------------

    return {
        "status": "success",
        "message": "Wazuh alert received and processed",
        "wazuh_alert": alert,
        "parsed_alert": parsed_alert.model_dump(),
        "soar_alert": soar_alert,
        "soar_result": result,
    }
