import { Component } from '@angular/core';

@Component({
  standalone: true,
  template: `
    <div class="card">
      <h1>Secured IDP Area</h1>
      <p>Requires FORM authentication (user1/password1).</p>
      <p><a class="btn" href="../FormLoginServlet">Login</a></p>
    </div>
  `
})
export class SecuredComponent {}
