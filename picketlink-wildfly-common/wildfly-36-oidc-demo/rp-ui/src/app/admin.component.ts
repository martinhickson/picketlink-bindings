import { Component, inject } from '@angular/core';
import { AsyncPipe, JsonPipe } from '@angular/common';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

interface DemoInfo {
  links?: {
    asDiscovery?: string;
    asJwks?: string;
  };
}

@Component({
  standalone: true,
  imports: [AsyncPipe, JsonPipe],
  template: `
    <div class="card">
      <h1>RP Admin &amp; OIDC Metadata</h1>
      @if (info$ | async; as info) {
        <div class="grid">
          <a class="btn" [href]="info.links?.asDiscovery" target="_blank">OIDC Discovery (AS)</a>
          <a class="btn" [href]="info.links?.asJwks" target="_blank">JWKS (AS)</a>
          <a class="btn" href="../api/info" target="_blank">CXF Demo Info (JSON)</a>
          <a class="btn btn-secondary" href="../LogoutServlet?LLO=true">Local logout (RP only)</a>
          <a class="btn btn-secondary" href="../LogoutServlet?GLO=true">Global logout (RP + AS)</a>
        </div>
        <h3>RP demo info (via Angular HttpClient)</h3>
        <pre>{{ info | json }}</pre>
      }
    </div>
  `
})
export class AdminComponent {
  private api = inject(ApiService);
  info$ = this.api.info() as Observable<DemoInfo>;
}
