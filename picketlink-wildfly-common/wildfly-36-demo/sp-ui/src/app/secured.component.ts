import { Component } from '@angular/core';

@Component({
  standalone: true,
  template: `
    <div class="card">
      <h1>Secured SP Area</h1>
      <p>If you see this page, SAML authentication succeeded via PicketLink on WildFly Elytron.</p>
      <div class="grid">
        <a class="btn" href="../app/secured/logout?GLO=true">Global logout (SP + IDP)</a>
        <a class="btn btn-secondary" href="../app/secured/logout?LLO=true">Local logout (SP only)</a>
        <a class="btn btn-secondary" href="../app/secured">Reload secured page</a>
      </div>
    </div>
  `
})
export class SecuredComponent {}
