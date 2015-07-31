class UsersController < ApplicationController

	def does_user_exist?(email)
		user = User.find_by(:user_email => email.downcase.to_s )

		if user
			return true
		else
			return false
		end
	end

	get '/' do
		authorization_check

		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)
		@users = User.order("lower(user_name) DESC").all

		erb :users, :locals => {'body_class' => 'users'}
	end

	get '/login' do
		#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)
		erb :'users/login', :locals => {'body_class' => 'users users--login'}
	end

	get '/signup' do
		#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)
		@user = session[:user]
		erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
	end

	get '/logout' do
		session[:user] = nil
		redirect '/'
	end

	post '/login' do
		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])
		if (!@nonce.valid? && @nonce.stale?)
			#return early if nonce bad/stale
			flash.message = "There was a problem with your login Please try again."
			erb :'users/login', :locals => {'body_class' => 'users users--login'}
	
		elsif (self.does_user_exist?(params[:user_email].downcase) != true)
			#return early if user does not exist
			flash.message = "Your username or password were incorrect. Please try again."
			erb :'users/login', :locals => {'body_class' => 'users users--login'}

		else
			#no user errors detected
			user = User.where(:user_email => params[:user_email].downcase).first!

			if user.password_hash == BCrypt::Engine.hash_secret(params[:user_password], user.password_salt)
				#success, render success template
				session[:user] = user
				@user = session[:user]
				
				erb :'users/thanks-login', :locals => {'body_class' => 'users users--login'}

			else
				#fallback error
				flash.message = "Your username or password were incorrect. Please try again."
				erb :'users/login', :locals => {'body_class' => 'users users--login'}
			end

		end
	end

	post '/signup' do
		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])
		
		if (!@nonce.valid? || @nonce.stale?)
			#return early if form nonce invalid
			flash.message = "Sorry, there was a problem adding you as a user. Please try again."
			erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
		
		elsif (params[:user_password].to_s != params[:user_password_confirm].to_s)
			#return early if password doesn't match confirmation password
			flash.message = "Your passwords did not match. Please try again."
			erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
		
		else
			@new_user = User.new
			@new_user.user_name = params[:user_name]
			@new_user.user_email = params[:user_email].downcase
			@new_user.is_admin = 0 #0 is false, 1 is true
			@new_user.created = Time.now

			password_salt = BCrypt::Engine.generate_salt
			password_hash = BCrypt::Engine.hash_secret(params[:user_password], password_salt)

			@new_user.password_salt = password_salt
			@new_user.password_hash = password_hash

			if @new_user.save
				erb :'users/thanks-signup', :locals => {'body_class' => 'users users--signup'}
			else
				flash.message = "Sorry, there was a problem creating you as a user. Please try again."
				erb :'users/signup', :locals => {'body_class' => 'users users--signup'}
			end
		end
	end

	get '/edit/:id' do
		authorization_check

		#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)

		@user = User.find(params[:id])

		if @user
			erb :'users/edit', :locals => {'body_class' => 'users users--edit'}
		else
			redirect not_found
		end
	end

	post '/edit' do
		authorization_check

		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])
		
		if (!@nonce.valid? || @nonce.stale?)
			#return early if form nonce invalid
			@user = @edited_user
			flash.message = "Sorry, there was a problem editing the user. Please try again."
			erb :'users/edit', :locals => {:id => params[:user_id], 'body_class' => 'users users--edit'}
		
		else
			@edited_user = User.find(params[:user_id])
			@edited_user.user_name = params[:user_name]
			@edited_user.user_email = params[:user_email].downcase
			@edited_user.is_admin = (params[:user_is_admin]) ? 1 : 0 #0 is false, 1 is true
			@edited_user.modified = Time.now

			if @edited_user.save
				@user = @edited_user
				flash.message = "You have successfully edited the user."
				erb :'users/edit', :locals => {:id => params[:user_id], 'body_class' => 'users users--edit'}
			else
				@user = @edited_user
				flash.message = "Sorry, there was a problem editing the user. Please try again."
				erb :'users/edit', :locals => {:id => params[:user_id], 'body_class' => 'users users--edit'}
			end
		end

	end

	get '/new' do
		authorization_check

		#NONCE_SECRET should be complex string, saved in /.config/nonce_configuration.rb
		@nonce = Rack::Auth::Digest::Nonce.new(Time.now, NONCE_SECRET)

		erb :'users/new', :locals => {'body_class' => 'users users--new'}	
	end

	post '/new' do
		authorization_check

		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])
		
		if (!@nonce.valid? || @nonce.stale?)
			#return early if form nonce invalid
			flash.message = "Sorry, there was a problem creating the user. Please try again."
			erb :'users/new', :locals => {'body_class' => 'users users--new'}
		
		elsif (params[:user_password].to_s != params[:user_password_confirm].to_s)
			#return early if password doesn't match confirmation password
			flash.message = "Your passwords did not match. Please try again."
			erb :'users/new', :locals => {'body_class' => 'users users--new'}
		
		else
			@new_user = User.new
			@new_user.user_name = params[:user_name]
			@new_user.user_email = params[:user_email].downcase
			@new_user.is_admin = 0 #0 is false, 1 is true
			@new_user.created = Time.now

			password_salt = BCrypt::Engine.generate_salt
			password_hash = BCrypt::Engine.hash_secret(params[:user_password], password_salt)

			@new_user.password_salt = password_salt
			@new_user.password_hash = password_hash

			if @new_user.save
				@users = User.order("lower(user_name) DESC").all
				flash.message = "Success! You have created a new user."
				erb :'users', :locals => {'body_class' => 'users users--new'}
			else
				flash.message = "Sorry, there was a problem creating the user. Please try again."
				erb :'users/new', :locals => {'body_class' => 'users users--new'}
			end
		end

	end

	post '/delete' do
		authorization_check

		@nonce = Rack::Auth::Digest::Nonce.parse(params[:nonce])

		@user = User.find(params[:user_id])
		if @user.destroy
			flash.message = "Success! You have destroyed a user."
			@users = User.order("lower(user_name) DESC").all
			erb :'users', :locals => {'body_class' => 'users'}
		else
			flash.message = "Sorry, there was a problem deleting the user. Please try again."
			@users = User.order("lower(user_name) DESC").all
			erb :'users', :locals => {'body_class' => 'users'}
		end
	end

end