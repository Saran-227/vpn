from fastapi import APIRouter
from ...services.dashboard_service import service
router = APIRouter(prefix='/api/vpn', tags=['vpn'])

@router.get('/status')
def status():
    return service.dashboard().vpn
