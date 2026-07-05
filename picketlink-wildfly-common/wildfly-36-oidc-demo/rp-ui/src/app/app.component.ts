import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <nav>
      <strong>PicketLink OIDC RP</strong>
      <a routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }">Home</a>
      <a routerLink="/secured" routerLinkActive="active">Secured App</a>
      <a routerLink="/admin" routerLinkActive="active">Admin / Metadata</a>
      <span class="nav-spacer"></span>
      <a class="btn btn-nav" href="../LogoutServlet?GLO=true">Logout</a>
    </nav>
    <main><router-outlet /></main>
  `
})
export class AppComponent {}
