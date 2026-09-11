from fastapi import APIRouter
from ...services.dashboard_service import service
router = APIRouter(prefix='/api/security', tags=['security'])

@router.get('/current')
def current(): return service.dashboard().security
@router.get('/history')
def history(): return [{'timestamp': p.timestamp, 'risk_score': p.risk_score} for p in service.dashboard().history]
