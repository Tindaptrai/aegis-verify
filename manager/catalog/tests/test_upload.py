"""Actual-byte limits apply independently of client-declared lengths."""
import io
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase
from catalog.upload import CatalogUploadMiddleware, MAX_REQUEST


class UploadBoundaryTests(SimpleTestCase):
    def test_falsified_small_content_length_cannot_bypass_finite_stream_read(self):
        request = RequestFactory().post('/api/v1/catalog/import', b'', content_type='application/octet-stream')
        request._stream = io.BytesIO(b'x' * (MAX_REQUEST + 1))
        request.META['CONTENT_LENGTH'] = '1'
        response = CatalogUploadMiddleware(lambda _: self.fail('Oversized body reached CSRF/view'))(request)
        self.assertEqual(response.status_code, 413)

    def test_non_upload_route_does_not_read_body_or_change_handlers(self):
        request = RequestFactory().post('/agent/v1/poll', b'bounded', content_type='application/json')
        response = CatalogUploadMiddleware(lambda incoming: HttpResponse(incoming.read()))(request)
        self.assertEqual(response.content, b'bounded')

    def test_multipart_nonfile_overhead_retains_general_64k_limit(self):
        request = RequestFactory().post('/api/v1/catalog/import', {'field': 'x' * 65537})
        response = CatalogUploadMiddleware(lambda _: self.fail('Oversized multipart fields reached view'))(request)
        self.assertEqual(response.status_code, 400)

    def test_malformed_multipart_is_fixed_api_error_before_csrf(self):
        request = RequestFactory().post('/api/v1/catalog/import', b'broken', content_type='multipart/form-data; boundary=')
        response = CatalogUploadMiddleware(lambda _: self.fail('Malformed multipart reached view'))(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b'{"error": {"code": "invalid_request"}}')
