from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio, os
from .api.routes import dashboard, vpn, metrics, security, events
from .services.dashboard_service import service

app = FastAPI(title='IPsec VPN Analyzer API', version='1.0.0')
allowed_origins = [x.strip() for x in os.getenv('CORS_ORIGINS', 'http://localhost:5173').split(',') if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=True, allow_methods=['GET'], allow_headers=['*'])
for router in (dashboard.router, vpn.router, metrics.router, security.router, events.router): app.include_router(router)

@app.get('/api/health')
def health(): return {'status':'ok', 'service':'ipsec-vpn-analyzer-api'}

@app.websocket('/ws/dashboard')
async def dashboard_ws(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            await ws.send_json(service.dashboard().model_dump(mode='json'))
            await asyncio.sleep(2)
    except (WebSocketDisconnect, RuntimeError):
        pass
