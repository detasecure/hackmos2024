from fastapi import FastAPI, File, UploadFile, HTTPException
from typing import Dict, Any
from cosmos_contract_scanner_v2 import CosmosContractScanner  # Assuming this is the uploaded file
import tempfile
import os
import json

app = FastAPI()

@app.post("/scan-contract")
async def scan_contract(file: UploadFile = File(...)) -> Dict[str, Any]:
    # Check file extension
    if not file.filename.endswith(".rs"):
        raise HTTPException(status_code=400, detail="Only .rs files are supported")

    # Create a temporary file to store the uploaded contract
    with tempfile.NamedTemporaryFile(delete=False, suffix=".rs") as tmp_file:
        tmp_file_path = tmp_file.name
        content = await file.read()
        tmp_file.write(content)

    try:
        # Initialize and run the scanner
        scanner = CosmosContractScanner(tmp_file_path)
        vulnerabilities = scanner.scan()
        report = scanner.generate_report()
    finally:
        # Clean up temporary file
        os.remove(tmp_file_path)

    return report

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
