class SapiError(Exception):
    def __init__(self, code: str = "invalid_message"):
        self.code = code
        super().__init__(code)
