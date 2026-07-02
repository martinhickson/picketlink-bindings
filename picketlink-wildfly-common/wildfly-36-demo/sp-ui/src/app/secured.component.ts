import { Component } from '@angular/core';

@Component({
  standalone: true,
  template: `
    <div class="card">
      <h1>Secured SP Area</h1>
      <p>If you see this page, SAML authentication succeeded via PicketLink on WildFly Elytron.</p>
      <p><a class="btn" href="../app/secured">Reload secured page</a></p>
    </div>
  `
})
export class SecuredComponent {}
