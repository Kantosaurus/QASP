from qasp_client import QASPClient

qasp = QASPClient("https://qasp.agis.it.com")
result = qasp.register("Aphrodite", [{"name": "echo", "description": "Echo input"}])
print(result)
