from fastapi import APIRouter
from ...services.dashboard_service import service
router = APIRouter(prefix='/api/metrics', tags=['metrics'])

@router.get('/current')
def current(): return service.dashboard().metrics
@router.get('/history')
def history(): return service.dashboard().history
