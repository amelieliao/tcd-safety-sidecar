# FILE: tcd/signals.py
class SignalProvider:
    def collect(self):
        return {}

class DefaultLLMSignals(SignalProvider):
    def collect(self):
        return {}