from typing import Optional

import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Header, HTTPException

from azure.azure_auth import checkAuthorization, init_azure_ad

tenantId = "xxxxx-xxxx-xxxx-xxxx-xxxxxxxxx"
appId = "xxxxx-xxxx-xxxx-xxxx-xxxxxxxxx"
init_azure_ad(tenantId, appId)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=False,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.post("/")
async def read_items(authorization: Optional[str] = Header(None)):
    error, req = checkAuthorization(token=authorization, scope='access_as_user')
    if error:
        raise HTTPException(status_code=req['status'], detail=req['error'])
    return {"authorization": authorization}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
