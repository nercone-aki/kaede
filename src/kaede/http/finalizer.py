from .models import HTTPRequest, HTTPResponse
from .server import HTTPServerRole

async def finalize_request(request: HTTPRequest, strict: bool = False):
    ...

async def finalize_response(response: HTTPResponse, strict: bool = False, role: HTTPServerRole = HTTPServerRole.ORIGIN):
    ...
