class MyAppRouter:
    def db_for_read(self, model, **hints):
        # Specify the app you want to route to the mini_data_lake database
        if model._meta.app_label == 'dmz_mini_dl':
            return 'mini_data_lake'
        return 'default'  # All other models go to the default database

    def db_for_write(self, model, **hints):
        if model._meta.app_label == 'dmz_mini_dl':
            return 'mini_data_lake'
        return 'default'  # All other models go to the default database

    def allow_relation(self, obj1, obj2, **hints):
        # Check the app labels of both objects
        app_label1 = obj1._meta.app_label
        app_label2 = obj2._meta.app_label
        
        # If both objects are from the specific app, allow the relation
        if app_label1 == 'dmz_mini_dl' and app_label2 == 'dmz_mini_dl':
            return True
        
        # If only one of them is from the specific app, disallow the relation
        if app_label1 == 'dmz_mini_dl' or app_label2 == 'dmz_mini_dl':
            return False
        
        # Allow relations between all other models
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label == 'dmz_mini_dl':
            return db == 'mini_data_lake'  # Migrate the specific app to the mini_data_lake database
        return db == 'default'  # All other apps migrate to the default database