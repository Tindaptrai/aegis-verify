"""Bound upload bytes before CSRF can trigger Django multipart parsing."""
import io
from django.core.files.uploadhandler import FileUploadHandler, StopUpload, TemporaryFileUploadHandler
from django.core.exceptions import RequestDataTooBig, TooManyFilesSent, TooManyFieldsSent
from django.http.multipartparser import MultiPartParserError
from accounts.views import api_error

MAX_REQUEST = 21 * 1024 * 1024
MAX_FILE = 20 * 1024 * 1024


class CatalogUploadHandler(FileUploadHandler):
    def new_file(self, *args, **kwargs):
        super().new_file(*args, **kwargs)
        self.received = 0

    def receive_data_chunk(self, raw_data, start):
        self.received += len(raw_data)
        if self.received > MAX_FILE:
            self.request.catalog_upload_overflow = True
            raise StopUpload(connection_reset=True)
        return raw_data

    def file_complete(self, file_size):
        return None


class CatalogUploadMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path_info == '/api/v1/catalog/import' and request.method == 'POST':
            # A finite read checks actual bytes independently of upload headers.
            raw = request.read(MAX_REQUEST + 1)
            if len(raw) > MAX_REQUEST:
                return api_error('package_too_large', 413)
            request._stream = io.BytesIO(raw)
            request._read_started = False
            request.upload_handlers = [CatalogUploadHandler(request), TemporaryFileUploadHandler(request)]
            try:
                # Parse only this route under the installed limits, so parser
                # failures also have the fixed API error shape before CSRF.
                if request.content_type == 'multipart/form-data':
                    request.POST
            except (RequestDataTooBig, TooManyFilesSent, TooManyFieldsSent, MultiPartParserError):
                return api_error('invalid_request', 400)
            if getattr(request, 'catalog_upload_overflow', False):
                return api_error('package_too_large', 413)
        response = self.get_response(request)
        if getattr(request, 'catalog_upload_overflow', False):
            return api_error('package_too_large', 413)
        return response
