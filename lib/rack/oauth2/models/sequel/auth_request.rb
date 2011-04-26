module Rack
  module OAuth2
    class Server

      # Authorization request. Represents request on behalf of client to access
      # particular scope. Use this to keep state from incoming authorization
      # request to grant/deny redirect.
      class AuthRequest < Sequel::Model(:auth_requests)
        unrestrict_primary_key
        
        class << self
          # Find AuthRequest from identifier.
          def find(request_id)
            self[:id => request_id]
          end

          # Create a new authorization request. This holds state, so in addition
          # to client ID and scope, we need to know the URL to redirect back to
          # and any state value to pass back in that redirect.
          def create(client, scope, redirect_uri, response_type, state)
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            fields = { :id              => Server.secure_random,
                       :client_id       => client.id, 
                       :scope           => scope, 
                       :redirect_uri    => client.redirect_uri || redirect_uri,
                       :response_type   => response_type, 
                       :state           => state,
                       :grant_code      => nil, 
                       :authorized_at   => nil,
                       :created_at      => Time.now, 
                       :revoked         => nil 
                     }
            super( fields )
          end

          def collection
            Server.database
          end
        end
        
        def scope
          JSON.parse( self[:scope] )
        end

        # Grant access to the specified identity.
        def grant!(identity)
          raise ArgumentError, "Must supply a identity" unless identity
          return if self.revoked
          client = Client[client_id] or return
          self.authorized_at = Time.now
          if response_type == "code" # Requested authorization code
            access_grant = AccessGrant.create(identity, client, scope, redirect_uri)
            self.grant_code = access_grant.code
            save unless self.revoked
          else # Requested access token
            access_token = AccessToken.get_token_for(identity, client, scope)
            self.access_token = access_token.token
            save unless self.revoked or self.access_token
          end
          true
        end

        # Deny access.
        def deny!
          self.authorized_at = Time.now
          save
        end

      end

    end
  end
end
