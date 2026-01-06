--
-- PostgreSQL database dump
--

\restrict jBfICzkd4kAaqzjdWp5x7diZY5G7hzCvrsReVID1WI4IVISaTHutXXJPsxc9wFJ

-- Dumped from database version 13.23
-- Dumped by pg_dump version 13.23

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: trigger_set_timestamp(); Type: FUNCTION; Schema: public; Owner: klarto_api_user
--

CREATE FUNCTION public.trigger_set_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


ALTER FUNCTION public.trigger_set_timestamp() OWNER TO klarto_api_user;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: users; Type: TABLE; Schema: public; Owner: klarto_api_user
--

CREATE TABLE public.users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    is_verified boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    verification_token character varying(255),
    verification_token_expires_at timestamp with time zone,
    password_reset_token character varying(255),
    password_reset_token_expires_at timestamp with time zone,
    profile_picture_url text,
    profile_picture_base64 text
);


ALTER TABLE public.users OWNER TO klarto_api_user;

--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: klarto_api_user
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: klarto_api_user
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: users set_timestamp; Type: TRIGGER; Schema: public; Owner: klarto_api_user
--

CREATE TRIGGER set_timestamp BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();


--
-- PostgreSQL database dump complete
--

\unrestrict jBfICzkd4kAaqzjdWp5x7diZY5G7hzCvrsReVID1WI4IVISaTHutXXJPsxc9wFJ

