REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'OTP Authentication Service',
    'DESCRIPTION': 'Email-based OTP authentication service',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
}
