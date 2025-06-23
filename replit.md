# SLRDX Project Management System

## Overview

SLRDX is a comprehensive project management web application built with Flask. The system provides role-based access control with three primary user types (Admin, Manager, User) and supports project creation, task management, team collaboration, document handling, and milestone tracking. The application follows a traditional MVC pattern with Flask as the backend framework and uses SQLAlchemy for database operations.

## System Architecture

### Backend Architecture
- **Framework**: Flask with SQLAlchemy ORM
- **Database**: SQLite for development (configured for PostgreSQL support)
- **Authentication**: Flask-Login with password hashing via Werkzeug
- **File Handling**: Local file storage with upload size limits (16MB)
- **Server**: Gunicorn WSGI server for production deployment

### Frontend Architecture
- **Templates**: Jinja2 templating engine with inheritance pattern
- **Styling**: Bootstrap 5.3.0 CSS framework with custom CSS
- **Icons**: Font Awesome 6.0.0 for UI icons
- **JavaScript**: Vanilla JavaScript for interactive features
- **Responsive Design**: Mobile-first approach with sidebar navigation

### Database Schema
The application uses a relational database model with the following key entities:
- **Users**: Authentication, roles, and hierarchical management structure
- **Projects**: Project lifecycle management with status tracking
- **Tasks**: Task assignment and progress tracking with dependencies
- **Comments**: Collaborative communication system
- **Documents**: File management with versioning support
- **Milestones**: Project checkpoint tracking
- **UserPermissions**: Granular access control system

## Key Components

### Authentication & Authorization
- Role-based access control (Admin, Manager, User)
- Hierarchical user management (managers can oversee users)
- Granular permission system for different modules (Projects, Tasks, Documents)
- Session management with Flask-Login

### Project Management
- Project creation with team assignment
- Status tracking (Just Started, In Progress, Completed)
- Progress calculation based on task completion
- Deadline management and overdue detection
- Milestone tracking system

### Task Management
- Task creation and assignment within projects
- Priority levels and status tracking
- Due date management with overdue notifications
- Task dependencies (manual and automatic)
- Outcome tracking for task completion verification

### Document Management
- File upload and storage system
- Document versioning capabilities
- Comment system for document collaboration
- Access control based on user permissions

### Team Collaboration
- User skill management for better task assignment
- Comment systems across projects, tasks, and documents
- Team member overview with statistics
- Permission management interface

## Data Flow

### User Authentication Flow
1. User submits credentials via login form
2. System validates against hashed passwords in database
3. Flask-Login creates user session
4. Role-based redirects to appropriate dashboard
5. Ongoing requests validated against session and permissions

### Project Creation Flow
1. Authorized user (Admin/Manager) creates project
2. System creates project record with creator assignment
3. Team members assigned through many-to-many relationship
4. Project appears in assigned users' dashboards
5. Tasks can be created within project scope

### Task Assignment Flow
1. Task created within project context
2. Optional assignment to specific user
3. Task inherits project permissions
4. Progress tracking updates project completion percentage
5. Approval workflow triggers for completed tasks

## External Dependencies

### Python Packages
- **Flask**: Web framework and core functionality
- **Flask-SQLAlchemy**: Database ORM and migrations
- **Flask-Login**: User session management
- **Werkzeug**: Password hashing and security utilities
- **Gunicorn**: Production WSGI server
- **email-validator**: Email validation for user registration
- **psycopg2-binary**: PostgreSQL database adapter

### Frontend Libraries
- **Bootstrap 5.3.0**: CSS framework from CDN
- **Font Awesome 6.0.0**: Icon library from CDN
- **Custom CSS**: Application-specific styling

### System Dependencies
- **OpenSSL**: SSL/TLS support
- **PostgreSQL**: Database system (configured but using SQLite in development)

## Deployment Strategy

### Development Environment
- Local SQLite database for rapid development
- Flask development server with debug mode
- Automatic code reloading enabled
- File uploads stored in local `uploads/` directory

### Production Environment
- Gunicorn WSGI server with auto-scaling deployment target
- ProxyFix middleware for proper header handling
- Environment-based configuration management
- Session secret from environment variables
- Database connection pooling with health checks

### Infrastructure Configuration
- **Replit Environment**: Configured for web, Python 3.11, and Node.js 20
- **Port Configuration**: Internal port 5000, external port 80
- **Auto-scaling**: Configured for automatic scaling based on demand
- **Process Management**: Gunicorn with reload capability for development

## Changelog

- June 23, 2025. Initial setup

## User Preferences

Preferred communication style: Simple, everyday language.