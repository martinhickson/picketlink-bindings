import { Component, inject } from '@angular/core';
import { AsyncPipe, JsonPipe } from '@angular/common';
import { ApiService } from './api.service';

@Component({
  standalone: true,
  imports: [AsyncPipe, JsonPipe],
  template: `
    <div class="card">
      <h1>Service Provider</h1>
      <p>This Angular SPA runs on the SP WildFly instance. Use <strong>Secured App</strong> to trigger SAML SSO against the IDP.</p>
      <h3>CXF REST: /api/info</h3>
      <pre>{{ info$ | async | json }}</pre>
    </div>
  `
})
export class HomeComponent {
  private api = inject(ApiService);
  info$ = this.api.info();
}
