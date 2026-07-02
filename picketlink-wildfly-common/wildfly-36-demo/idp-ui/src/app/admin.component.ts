import { Component, inject } from '@angular/core';
import { AsyncPipe, JsonPipe } from '@angular/common';
import { ApiService } from './api.service';

@Component({
  standalone: true,
  imports: [AsyncPipe, JsonPipe],
  template: `
    <div class="card">
      <h1>IDP Admin &amp; Metadata</h1>
      <div class="grid">
        <a class="btn" href="../metadata" target="_blank">SAML Metadata (XML)</a>
        <a class="btn" href="../api/admin/federation/metadata" target="_blank">Metadata Summary (JSON)</a>
        <a class="btn" href="../api/info" target="_blank">CXF Demo Info (JSON)</a>
        <a class="btn btn-secondary" href="../LogoutServlet">Logout</a>
      </div>
      <h3>Metadata JSON</h3>
      <pre>{{ metadata$ | async | json }}</pre>
    </div>
  `
})
export class AdminComponent {
  private api = inject(ApiService);
  metadata$ = this.api.metadataJson();
}
