module Rack
  module OAuth2
    class Server
      
      # The access grant is a nonce, new grant created each time we need it and
      # good for redeeming one access token.
      class AccessGrant < Sequel::Model(:access_grants)
        unrestrict_primary_key
        class << self
          # Find AccessGrant from authentication code.
          def from_code(code)
            self[:id=>code, :revoked=>nil]
          end

          # Create a new access grant.
          def create(identity, client, scope, redirect_uri = nil, expires = nil)
            puts "foo"
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            expires_at = Time.now + (expires || 300) 
            fields = { :id => Server.secure_random, 
                       :identity     => identity, 
                       :scope        => scope,
                       :client_id    => client.id, 
                       :redirect_uri => client.redirect_uri || redirect_uri,
                       :created_at   => Time.now, 
                       :expires_at   => expires_at, 
                       :granted_at   => nil,
                       :access_token => nil, 
                       :revoked      => nil 
                     }
            
            super(fields)
          end

          def collection
            Server.database
          end
        end
        
        alias :code :id

        # Authorize access and return new access token.
        #
        # Access grant can only be redeemed once, but client can make multiple
        # requests to obtain it, so we need to make sure only first request is
        # successful in returning access token, futher requests raise
        # InvalidGrantError.
        def authorize!
          raise InvalidGrantError, "You can't use the same access grant twice" if self.access_token || self.revoked
          client = Client.find(client_id) or raise InvalidGrantError
          access_token = AccessToken.get_token_for(identity, client, JSON.parse( scope ))
          self.access_token = access_token.token
          self.granted_at = Time.now
          save
          return access_token
        end

        def revoke!
          self.revoked = Time.now
          save unless self.revoked
        end
        
        def expires_at
          self[:expires_at].to_i
        end

      end

    end
  end
end
