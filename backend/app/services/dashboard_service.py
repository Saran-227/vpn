import os
from ..integrations.mock_data_provider import provider
from ..integrations.asim_adapter import AsimAdapter
from ..integrations.sermistha_adapter import SermisthaAdapter

class DashboardService:
    def __init__(self):
        self.mode = os.getenv('DATA_MODE', 'MOCK').upper()
        self.asim = AsimAdapter()
        self.sermistha = SermisthaAdapter()

    def dashboard(self):
        if self.mode == 'MOCK':
            return provider.snapshot()
        raise RuntimeError('REAL mode is enabled, but Asim/Sermistha adapters are placeholders. Implement their final schema mappings first.')

service = DashboardService()
