package com.ign.oauth.util;

import javax.persistence.*;

public class PersistenceService {
    private static String DEFAULT_PU = "OAuthFilterPU";
    private EntityManager em;
    private EntityTransaction tx;

    private static ThreadLocal<PersistenceService> instance = new ThreadLocal<PersistenceService>() {
        @Override
        protected PersistenceService initialValue() {
            return new PersistenceService();
        }
    };

    private PersistenceService() {
        EntityManagerFactory emf = Persistence.createEntityManagerFactory(DEFAULT_PU);
        this.em = emf.createEntityManager();
    }

    public EntityManager getEntityManager() {
        return em;
    }

    public static PersistenceService getInstance() {
        return instance.get();
    }

    private static void removeInstance() {
        instance.remove();
    }

    public void refreshEntity(Object entity) {
        em.refresh(entity);
    }

    public <T> T mergeEntity(T entity) {
        return em.merge(entity);
    }

    public void persistEntity(Object entity) {
        em.persist(entity);
    }

    public void removeEntity(Object entity) {
        em.remove(entity);
    }

    public Query createNamedQuery(String query) {
        return em.createNamedQuery(query);
    }

    public Query createQuery(String query) {
        return em.createQuery(query);
    }

    public Query createNativeQuery(String query) {
        return em.createNativeQuery(query);
    }

    public void beginTx() {
        try {
            this.tx = em.getTransaction();
            tx.begin();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public void commitTx() {
        try {
            tx.commit();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public void rollbackTx() {
        try {
            tx.rollback();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public void close() {
        removeInstance();
    }
}
