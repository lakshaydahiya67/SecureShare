from django.urls import path
from . import views

urlpatterns = [
    # REST API endpoints only - no template views here
    path('upload/', views.FileUploadView.as_view(), name='api-file-upload'),
    path('list/', views.FileListView.as_view(), name='api-file-list'),
    path('download-link/<int:file_id>/', views.FileDownloadLinkView.as_view(), name='api-file-download-link'),
    path('download/<str:token>/', views.FileDownloadView.as_view(), name='api-file-download'),
    path('summarize/<int:file_id>/', views.FileSummarizeView.as_view(), name='api-file-summarize'),
]