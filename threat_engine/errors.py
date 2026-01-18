# threat_engine/errors.py

class ThreatEngineError(Exception): pass
class ValidationError(ThreatEngineError): pass
class RuleError(ThreatEngineError): pass
class DecisionError(ThreatEngineError): pass
class EnforcementError(ThreatEngineError): pass
