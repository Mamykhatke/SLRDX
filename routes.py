import os
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import app, db
from models import User, Project, Task, Comment, Document, UserPermission, Milestone, UserType, DocumentComment, DocumentVersion

# Authentication routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'Admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'Manager':
            return redirect(url_for('manager_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        manager_id = request.form.get('manager_id')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('auth/register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return render_template('auth/register.html')
        
        # Create new user
        user = User(username=username, email=email, role=role)
        if manager_id:
            user.manager_id = manager_id
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Set default permissions for non-admin users
        if role != 'Admin':
            default_permissions = [
                ('Proj', 'View'), ('Proj-team', 'View'), ('Proj doc', 'View'), 
                ('Proj Dis.', 'View'), ('task', 'View')
            ]
            for module, action in default_permissions:
                permission = UserPermission(user_id=user.id, module=module, action=action, granted=True)
                db.session.add(permission)
            db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    # Get managers for assignment
    managers = User.query.filter_by(role='Manager').all()
    return render_template('auth/register.html', managers=managers)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# Dashboard routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        abort(403)
    
    # Get statistics
    total_projects = Project.query.count()
    active_projects = Project.query.filter(Project.status.in_(['Just Started', 'In Progress'])).count()
    completed_projects = Project.query.filter_by(status='Completed').count()
    
    total_tasks = Task.query.count()
    completed_tasks = Task.query.filter_by(status='Completed').count()
    pending_tasks = Task.query.filter_by(status='Pending').count()
    overdue_tasks = Task.query.filter(Task.deadline < datetime.now().date(), Task.status != 'Completed').count()
    
    # Recent projects
    recent_projects = Project.query.order_by(Project.created_at.desc()).limit(3).all()
    
    # Upcoming deadlines
    upcoming_deadlines = Task.query.filter(
        Task.deadline >= datetime.now().date(),
        Task.status != 'Completed'
    ).order_by(Task.deadline.asc()).limit(5).all()
    
    return render_template('dashboard/admin.html',
                         total_projects=total_projects,
                         active_projects=active_projects,
                         completed_projects=completed_projects,
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks,
                         pending_tasks=pending_tasks,
                         overdue_tasks=overdue_tasks,
                         recent_projects=recent_projects,
                         upcoming_deadlines=upcoming_deadlines)

@app.route('/manager/dashboard')
@login_required
def manager_dashboard():
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    # Get accessible projects and tasks
    projects = current_user.get_accessible_projects()
    tasks = current_user.get_accessible_tasks()
    
    # Calculate statistics
    total_projects = len(projects)
    active_projects = len([p for p in projects if p.status in ['Just Started', 'In Progress']])
    completed_projects = len([p for p in projects if p.status == 'Completed'])
    
    total_tasks = len(tasks)
    completed_tasks = len([t for t in tasks if t.status == 'Completed'])
    pending_tasks = len([t for t in tasks if t.status == 'Pending'])
    overdue_tasks = len([t for t in tasks if t.is_overdue()])
    
    # Recent projects and upcoming deadlines
    recent_projects = sorted(projects, key=lambda x: x.created_at, reverse=True)[:3]
    upcoming_deadlines = sorted([t for t in tasks if t.deadline and t.status != 'Completed'], 
                               key=lambda x: x.deadline)[:5]
    
    return render_template('dashboard/manager.html',
                         total_projects=total_projects,
                         active_projects=active_projects,
                         completed_projects=completed_projects,
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks,
                         pending_tasks=pending_tasks,
                         overdue_tasks=overdue_tasks,
                         recent_projects=recent_projects,
                         upcoming_deadlines=upcoming_deadlines)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    # Get accessible projects and tasks
    projects = current_user.get_accessible_projects()
    tasks = current_user.get_accessible_tasks()
    
    # Calculate statistics
    total_projects = len(projects)
    active_projects = len([p for p in projects if p.status in ['Just Started', 'In Progress']])
    completed_projects = len([p for p in projects if p.status == 'Completed'])
    
    total_tasks = len(tasks)
    completed_tasks = len([t for t in tasks if t.status == 'Completed'])
    pending_tasks = len([t for t in tasks if t.status == 'Pending'])
    overdue_tasks = len([t for t in tasks if t.is_overdue()])
    
    # Recent projects and upcoming deadlines
    recent_projects = sorted(projects, key=lambda x: x.created_at, reverse=True)[:3]
    upcoming_deadlines = sorted([t for t in tasks if t.deadline and t.status != 'Completed'], 
                               key=lambda x: x.deadline)[:5]
    
    return render_template('dashboard/user.html',
                         total_projects=total_projects,
                         active_projects=active_projects,
                         completed_projects=completed_projects,
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks,
                         pending_tasks=pending_tasks,
                         overdue_tasks=overdue_tasks,
                         recent_projects=recent_projects,
                         upcoming_deadlines=upcoming_deadlines)

# Project routes
@app.route('/projects')
@login_required
def projects_list():
    projects = current_user.get_accessible_projects()
    return render_template('projects/list.html', projects=projects)

@app.route('/projects/create', methods=['GET', 'POST'])
@login_required
def create_project():
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        deadline = request.form.get('deadline')
        assigned_users = request.form.getlist('assigned_users')
        
        project = Project(
            title=title,
            description=description,
            created_by_id=current_user.id
        )
        
        if deadline:
            project.deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        
        db.session.add(project)
        db.session.flush()  # To get the project ID
        
        # Assign users to project
        for user_id in assigned_users:
            user = User.query.get(user_id)
            if user:
                project.assigned_users.append(user)
        
        db.session.commit()
        flash('Project created successfully!', 'success')
        return redirect(url_for('projects_list'))
    
    # Get users that can be assigned based on role
    if current_user.role == 'Admin':
        assignable_users = User.query.all()
    else:  # Manager
        assignable_users = current_user.managed_users.all()
    
    return render_template('projects/create.html', assignable_users=assignable_users)

@app.route('/projects/<int:project_id>')
@login_required
def view_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has access to this project
    accessible_projects = current_user.get_accessible_projects()
    if project not in accessible_projects:
        abort(403)
    
    tasks = project.tasks.all()
    comments = project.comments.order_by(Comment.created_at.desc()).all()
    documents = project.documents.all()
    
    return render_template('projects/view.html', 
                         project=project, 
                         tasks=tasks, 
                         comments=comments,
                         documents=documents)

@app.route('/projects/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager'] or \
       (current_user.role == 'Manager' and project.created_by_id != current_user.id):
        abort(403)
    
    if request.method == 'POST':
        project.title = request.form['title']
        project.description = request.form['description']
        project.status = request.form['status']
        deadline = request.form.get('deadline')
        
        if deadline:
            project.deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        else:
            project.deadline = None
        
        # Update assigned users
        assigned_users = request.form.getlist('assigned_users')
        project.assigned_users.clear()
        for user_id in assigned_users:
            user = User.query.get(user_id)
            if user:
                project.assigned_users.append(user)
        
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('view_project', project_id=project.id))
    
    # Get users that can be assigned
    if current_user.role == 'Admin':
        assignable_users = User.query.all()
    else:  # Manager
        assignable_users = current_user.managed_users.all()
    
    return render_template('projects/edit.html', 
                         project=project, 
                         assignable_users=assignable_users)

# Task routes
@app.route('/tasks')
@login_required
def tasks_list():
    tasks = current_user.get_accessible_tasks()
    return render_template('tasks/list.html', tasks=tasks)

@app.route('/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task():
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        project_id = request.form['project_id']
        assigned_to_id = request.form.get('assigned_to_id')
        priority = request.form['priority']
        deadline = request.form.get('deadline')
        
        task = Task(
            title=title,
            description=description,
            project_id=project_id,
            created_by_id=current_user.id,
            priority=priority
        )
        
        if assigned_to_id:
            task.assigned_to_id = assigned_to_id
        
        if deadline:
            task.deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        
        db.session.add(task)
        db.session.commit()
        
        # Update project progress
        project = Project.query.get(project_id)
        project.update_progress()
        
        flash('Task created successfully!', 'success')
        return redirect(url_for('tasks_list'))
    
    # Get accessible projects and assignable users
    projects = current_user.get_accessible_projects()
    if current_user.role == 'Admin':
        assignable_users = User.query.all()
    else:  # Manager
        assignable_users = current_user.managed_users.all()
    
    return render_template('tasks/create.html', 
                         projects=projects, 
                         assignable_users=assignable_users)

@app.route('/tasks/<int:task_id>')
@login_required
def view_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has access to this task
    accessible_tasks = current_user.get_accessible_tasks()
    if task not in accessible_tasks:
        abort(403)
    
    comments = task.comments.order_by(Comment.created_at.desc()).all()
    documents = task.documents.all()
    
    return render_template('tasks/view.html', 
                         task=task, 
                         comments=comments,
                         documents=documents)

@app.route('/tasks/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager'] or \
       (current_user.role == 'Manager' and task.created_by_id != current_user.id):
        abort(403)
    
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        task.status = request.form['status']
        task.priority = request.form['priority']
        assigned_to_id = request.form.get('assigned_to_id')
        deadline = request.form.get('deadline')
        
        if assigned_to_id:
            task.assigned_to_id = assigned_to_id
        else:
            task.assigned_to_id = None
            
        if deadline:
            task.deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        else:
            task.deadline = None
        
        db.session.commit()
        
        # Update project progress
        task.project.update_progress()
        
        flash('Task updated successfully!', 'success')
        return redirect(url_for('view_task', task_id=task.id))
    
    # Get users that can be assigned
    if current_user.role == 'Admin':
        assignable_users = User.query.all()
    else:  # Manager
        assignable_users = current_user.managed_users.all()
    
    return render_template('tasks/edit.html', 
                         task=task, 
                         assignable_users=assignable_users)

@app.route('/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user can mark this task as complete
    if task.assigned_to_id != current_user.id and current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    task.mark_completed()
    flash('Task marked as completed!', 'success')
    return redirect(url_for('view_task', task_id=task.id))

# Comment routes
@app.route('/projects/<int:project_id>/comment', methods=['POST'])
@login_required
def add_project_comment(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has access to this project
    accessible_projects = current_user.get_accessible_projects()
    if project not in accessible_projects:
        abort(403)
    
    content = request.form['content']
    comment = Comment(
        content=content,
        author_id=current_user.id,
        project_id=project_id
    )
    
    db.session.add(comment)
    db.session.commit()
    
    flash('Comment added successfully!', 'success')
    return redirect(url_for('view_project', project_id=project_id))

@app.route('/tasks/<int:task_id>/comment', methods=['POST'])
@login_required
def add_task_comment(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has access to this task
    accessible_tasks = current_user.get_accessible_tasks()
    if task not in accessible_tasks:
        abort(403)
    
    content = request.form['content']
    comment = Comment(
        content=content,
        author_id=current_user.id,
        task_id=task_id
    )
    
    db.session.add(comment)
    db.session.commit()
    
    flash('Comment added successfully!', 'success')
    return redirect(url_for('view_task', task_id=task_id))

# Document upload routes
@app.route('/projects/<int:project_id>/upload', methods=['POST'])
@login_required
def upload_project_document(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has access to this project
    accessible_projects = current_user.get_accessible_projects()
    if project not in accessible_projects:
        abort(403)
    
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('view_project', project_id=project_id))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('view_project', project_id=project_id))
    
    if file:
        filename = secure_filename(file.filename)
        # Add timestamp to avoid filename conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        document = Document(
            filename=filename,
            original_filename=file.filename,
            file_size=os.path.getsize(file_path),
            uploaded_by_id=current_user.id,
            project_id=project_id
        )
        
        db.session.add(document)
        db.session.commit()
        
        flash('Document uploaded successfully!', 'success')
    
    return redirect(url_for('view_project', project_id=project_id))

@app.route('/tasks/<int:task_id>/upload', methods=['POST'])
@login_required
def upload_task_document(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has access to this task
    accessible_tasks = current_user.get_accessible_tasks()
    if task not in accessible_tasks:
        abort(403)
    
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('view_task', task_id=task_id))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('view_task', task_id=task_id))
    
    if file:
        filename = secure_filename(file.filename)
        # Add timestamp to avoid filename conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        document = Document(
            filename=filename,
            original_filename=file.filename,
            file_size=os.path.getsize(file_path),
            uploaded_by_id=current_user.id,
            task_id=task_id
        )
        
        db.session.add(document)
        db.session.commit()
        
        flash('Document uploaded successfully!', 'success')
    
    return redirect(url_for('view_task', task_id=task_id))

@app.route('/download/<int:document_id>')
@login_required
def download_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    # Check if user has access to this document
    if document.project_id:
        accessible_projects = current_user.get_accessible_projects()
        if document.project not in accessible_projects:
            abort(403)
    elif document.task_id:
        accessible_tasks = current_user.get_accessible_tasks()
        if document.task not in accessible_tasks:
            abort(403)
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], 
                             document.filename, 
                             as_attachment=True,
                             download_name=document.original_filename)

# Team management routes
@app.route('/team')
@login_required
def team_list():
    if current_user.role == 'Admin':
        users = User.query.all()
    elif current_user.role == 'Manager':
        users = current_user.managed_users.all()
    else:
        abort(403)
    
    return render_template('team/manage.html', users=users)

@app.route('/team/<int:user_id>/permissions', methods=['GET', 'POST'])
@login_required
def manage_permissions(user_id):
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Managers can only manage their own team members
    if current_user.role == 'Manager' and user.manager_id != current_user.id:
        abort(403)
    
    if request.method == 'POST':
        # Clear existing permissions
        UserPermission.query.filter_by(user_id=user.id).delete()
        
        # Add new permissions
        modules = ['Proj', 'Proj-team', 'Proj doc', 'Proj Dis.', 'task']
        actions = ['View', 'Add', 'Edit', 'Delete', 'Download']
        
        for module in modules:
            for action in actions:
                field_name = f"{module}_{action}".replace(' ', '_').replace('.', '_').replace('-', '_')
                if request.form.get(field_name):
                    permission = UserPermission(
                        user_id=user.id,
                        module=module,
                        action=action,
                        granted=True
                    )
                    db.session.add(permission)
        
        db.session.commit()
        flash('Permissions updated successfully!', 'success')
        return redirect(url_for('team_list'))
    
    # Get current permissions
    permissions = {}
    for perm in user.permissions:
        key = f"{perm.module}_{perm.action}".replace(' ', '_').replace('.', '_').replace('-', '_')
        permissions[key] = perm.granted
    
    return render_template('team/permissions.html', user=user, permissions=permissions)
