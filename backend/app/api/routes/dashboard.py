from fastapi import APIRouter
from ...services.dashboard_service import service
router = APIRouter(prefix='/api', tags=['dashboard'])

@router.get('/dashboard')
def dashboard():
    return service.dashboard()
