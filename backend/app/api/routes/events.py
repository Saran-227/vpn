from fastapi import APIRouter
from ...services.dashboard_service import service
router = APIRouter(prefix='/api/events', tags=['events'])

@router.get('')
def events(): return service.dashboard().events
